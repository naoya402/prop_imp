#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define ETH_LEN 14     // VLAN 無し
#define IP_LEN  20
#define SID_LEN 32
#define PUB_LEN 32
#define SEC_LEN 32
#define KEY_LEN 32
#define SIG_LEN 64
#define IV_LEN  12
#define TAG_LEN 16
#define MAX_PTXT 1024
#define MAX_PKT  2048
#define MAX_STATE  8

#define ROUTERS 4
#define NODES   (ROUTERS+2)

typedef enum { SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;

// ========= L2/L3 (Ether/IPv4) ヘッダ =========
typedef struct {
    unsigned char dst[6];
    unsigned char src[6];
    uint16_t ethertype;    // 0x0800 = IPv4
} __attribute__((packed)) EthHdr;

typedef struct {
    uint8_t  ver_ihl;      // version(4) | IHL(4)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t hdr_checksum;
    uint32_t src;
    uint32_t dst;
    // options may follow (IHL>5)
} __attribute__((packed)) IPv4Hdr;

// ---- 共通ヘッダ ----
// SID(32) | STATUS(1) | DEST(4)
typedef struct {
    unsigned char sid[SID_LEN];  // セッションID
    uint8_t status;              // ステータス (SETUP_REQ, SETUP_RESP, DATA_TRANS)
    unsigned char dest[4];       // 宛先アドレス

    // SETUP_REQ / SETUP_RESP ヘッダ: πリスト情報
    uint16_t pi_concat_len;           // π リスト長
    unsigned char *pi_concat;         // π リストデータ

    // SETUP_RESP ヘッダ: DST_S 情報
    uint16_t dst_s_len;                // DST_S 長
    unsigned char dst_s[SIG_LEN];             // DST_S データ

} Oheader;

// ---- ペイロード ----
typedef struct {
    // ---- SETUP_REQ / SETUP_RESP ----
    unsigned char peer_pub[PUB_LEN];  // 公開鍵 (k_C または k_S)

    // SETUP_REQ
    uint16_t tau_len;
    unsigned char *tau[SIG_LEN];       //検証用の署名

    // SETUP_RESP
    unsigned char rand_val[4];        //検証用の乱数

    // ---- DATA_TRANS ----
    unsigned char iv[IV_LEN];         // GCM-IV
    size_t ct_len;                    // 暗号文長
    unsigned char ct[MAX_PTXT];       // 暗号文
    unsigned char tag[TAG_LEN];       // GCM-タグ
} Payload;

typedef struct {
    Oheader  h;
    Payload p;
} Packet;

typedef struct {
    int id;
    char name[8];
    unsigned char addr[4];
    unsigned char rand_val[4];


    // X25519 (DH)
    EVP_PKEY *dh_sk;
    // X25519鍵
    EVP_PKEY *sk;
    EVP_PKEY *pk;

    // セッション鍵（確立後に使用）
    unsigned char sess_key[KEY_LEN];
    int has_sess;

    // SIDに紐づく前後ホップ状態
    struct {
        int used;
        unsigned char sid[SID_LEN];
        char prev_addr; //本来アドレスだが便宜上ノードID
        char next_addr; //本来アドレスだが便宜上ノードID
        unsigned char tau[SIG_LEN];   // NEW: このノードが生成した τ
        size_t tau_len;
    } state[MAX_STATE];
} Node;


static void die(const char *msg) {
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void die_ossl(const char *msg) {
    fprintf(stderr, "OpenSSL ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static EVP_PKEY* gen_x25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");
    EVP_PKEY *p = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("keygen_init");
    if (EVP_PKEY_keygen(ctx, &p) <= 0) die("keygen");
    EVP_PKEY_CTX_free(ctx);
    return p;
}

static EVP_PKEY* import_x25519_pub(const unsigned char *pub) {
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, PUB_LEN);
    if (!p) die("new_raw_public_key");
    return p;
}

static EVP_PKEY* gen_ed25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) die_ossl("EVP_PKEY_CTX_new_id");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die_ossl("EVP_PKEY_keygen_init");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) die_ossl("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY* extract_public_only(const EVP_PKEY *priv) {
    unsigned char pub[PUB_LEN];
    size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(priv, pub, &publen) <= 0)
        die_ossl("EVP_PKEY_get_raw_public_key");
    EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, publen);
    if (!pubkey) die_ossl("EVP_PKEY_new_raw_public_key");
    return pubkey;
}

static void hash_sid_from_pub(const unsigned char *pub, unsigned char sid[SID_LEN]) {
    SHA256(pub, PUB_LEN, sid);
}

static void get_raw_pub(const EVP_PKEY *pkey, unsigned char pub[PUB_LEN]) {
    size_t len = PUB_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0 || len != PUB_LEN) die("get_raw_public_key");
}

static unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen) {
    *outlen = alen + blen;
    unsigned char *buf = malloc(*outlen);
    if (!buf) die("malloc failed");
    memcpy(buf, a, alen);
    memcpy(buf + alen, b, blen);
    return buf;
}

// X25519 共有秘密の導出
static void derive_shared(const EVP_PKEY *my_sk, const EVP_PKEY *peer_pub, unsigned char sec[SEC_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)my_sk, NULL);
    if (!ctx) die("derive ctx");
    if (EVP_PKEY_derive_init(ctx) <= 0) die("derive_init");
    if (EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY*)peer_pub) <= 0) die("set_peer");
    size_t outlen = SEC_LEN;
    if (EVP_PKEY_derive(ctx, sec, &outlen) <= 0 || outlen != SEC_LEN) die("derive");
    EVP_PKEY_CTX_free(ctx);
}

// AES-GCM暗号化
static void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]) {
    RAND_bytes(iv, IV_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("cipher ctx");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("enc_init1");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) die("set_ivlen");
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) die("enc_init2");
    int len;
    if (EVP_EncryptUpdate(ctx, NULL, &len, sid, SID_LEN) != 1) die("aad");
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) die("enc_upd");
    int ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) die("enc_fin");
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) die("get_tag");
    EVP_CIPHER_CTX_free(ctx);
}

static int aead_decrypt(const unsigned char key[KEY_LEN], const unsigned char *ct, size_t ct_len, const unsigned char sid[SID_LEN], const unsigned char iv[IV_LEN], const unsigned char tag[TAG_LEN], unsigned char *pt_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("cipher ctx");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("dec_init1");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) die("set_ivlen");
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) die("dec_init2");
    int len, ptlen;
    if (EVP_DecryptUpdate(ctx, NULL, &len, sid, SID_LEN) != 1) die("aad");
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) die("dec_upd");
    ptlen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) die("set_tag");
    int ok = EVP_DecryptFinal_ex(ctx, pt_out + ptlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1; // 1=auth OK
}

// Ed25519 署名・検証
static void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char **sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) <= 0)
        die_ossl("EVP_DigestSignInit");
    if (EVP_DigestSign(mdctx, NULL, siglen, data, datalen) <= 0)
        die_ossl("EVP_DigestSign (len)");
    *sig = (unsigned char*)OPENSSL_malloc(*siglen);
    if (!*sig) die_ossl("malloc");
    if (EVP_DigestSign(mdctx, *sig, siglen, data, datalen) <= 0)
        die_ossl("EVP_DigestSign");
    EVP_MD_CTX_free(mdctx);
}

static int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk) <= 0)
        die_ossl("EVP_DigestVerifyInit");
    int ok = EVP_DigestVerify(mdctx, sig, siglen, data, datalen);
    EVP_MD_CTX_free(mdctx);
    return ok == 1;
}

// ノード操作
static void node_init(Node *node, int id, const char *name) {
    memset(node, 0, sizeof(Node));
    snprintf(node->name, sizeof(node->name), "%s", name);
    node->id = id;
    node->sk = gen_ed25519_keypair();
    node->pk = extract_public_only(node->sk);
    RAND_bytes(node->addr, sizeof(node->addr));
    RAND_bytes(node->rand_val, sizeof(node->rand_val));
}

static void node_free(Node *n) {
    if (n->dh_sk) EVP_PKEY_free(n->dh_sk);
    if (n->sk) EVP_PKEY_free(n->sk);
    if (n->pk) EVP_PKEY_free(n->pk);
}

// ステート操作
static void state_set(Node *n, const unsigned char sid[SID_LEN], char prev_addr, int next_addr, const unsigned char *tau, size_t tau_len) {
    for (int i=0;i<MAX_STATE;i++) {
        if (!n->state[i].used) {
            n->state[i].used = 1;
            memcpy(n->state[i].sid, sid, SID_LEN);
            n->state[i].prev_addr = prev_addr;
            n->state[i].next_addr = next_addr;
            if (tau && tau_len > 0) {
                memcpy(n->state[i].tau, tau, tau_len);
                n->state[i].tau_len = tau_len;
            }
            return;
        }
    }
    die("state full");
}

static int state_get_next(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].next_addr;
    }
    return -1;
}

static int state_get_prev(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].prev_addr;
    }
    return -1;
}

const unsigned char* state_get_tau(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].tau;
    }
    return NULL;
}


//========= オーバーレイ領域ヘッダ & ペイロード=========
static size_t overlay_header_footprint(void) { return SID_LEN + 1 + 4; }//固定へッダ長

// L2/L3 ダミーを埋めて最小 IPv4 ヘッダ(IHL = 5)作成
static size_t write_l2l3_min(unsigned char *buf, size_t buf_cap) {
    if (buf_cap < ETH_LEN + sizeof(IPv4Hdr)) die("buf too small for L2/L3");
    EthHdr *eth = (EthHdr*)buf;
    memset(eth->dst, 0xff, 6);
    memset(eth->src, 0x11, 6);
    eth->ethertype = htons(0x0800);
    IPv4Hdr *ip = (IPv4Hdr*)(buf + ETH_LEN);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = (4<<4) | 5; // ver=4, IHL=5 => 20B
    ip->ttl = 64;
    ip->proto = 0xFD; // experimental
    return ETH_LEN + sizeof(IPv4Hdr);
}

// ======== オーバーレイのビルド/パース ========
static size_t ipv4_header_len_bytes(const IPv4Hdr *ip) {
    return 4 * (ip->ver_ihl & 0x0F); // IHL * 4
}

static size_t l3_overlay_offset(const unsigned char *l2) {
    const EthHdr *eth = (const EthHdr*)l2;
    (void)eth; // VLAN 無し前提。VLAN 対応は実運用で追加。
    const IPv4Hdr *ip = (const IPv4Hdr*)(l2 + ETH_LEN);
    return ETH_LEN + ipv4_header_len_bytes(ip); // 14 + IHL*4
}

// SETUP_REQ を 34B(=L3末) から書く
static size_t build_overlay_setup_req(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    uint16_t pi_concat_len = htons(pkt->h.pi_concat_len);
    uint16_t tau_len = htons(pkt->p.tau_len);
    size_t need = off + overlay_header_footprint() + 2 + pkt->h.pi_concat_len + PUB_LEN + 2 + pkt->p.tau_len;
    if (cap < need) die("cap too small (setup req)");
    unsigned char *p = l2 + off; //現在の位置 ＋ L2L3オフセット
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    memcpy(p, pkt->h.dest, 4); p += 4;
    memcpy(p, &pi_concat_len, 2); p += 2;
    memcpy(p, pkt->h.pi_concat, pkt->h.pi_concat_len); p += pkt->h.pi_concat_len;
    // printf("(%zu bytes)\n", (size_t)(p - l2 - off));
    // ぺイロード
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN;
    memcpy(p, &tau_len, 2); p += 2;
    memcpy(p, pkt->p.tau, pkt->p.tau_len); p += pkt->p.tau_len;
    return (size_t)(p - l2 - off); // 書き終わったバイト位置
}

// SETUP_RESP を書く（DST_S/πリスト付き）
static size_t build_overlay_setup_resp(unsigned char *l2, size_t cap, const Packet *pkt) {//, const unsigned char *pi_concat, uint16_t pi_concat_len, const unsigned char *dst_s, uint16_t dst_s_len) {
    size_t off = l3_overlay_offset(l2);
    size_t need = off + overlay_header_footprint() + PUB_LEN + 2 + pkt->h.pi_concat_len + 2 + pkt->h.dst_s_len;
    // printf("(%zu bytes)\n", need - off);
    if (cap < need) die("cap too small (setup resp)");
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    memcpy(p, pkt->h.dest, 4); p += 4; //37
    uint16_t n = htons(pkt->h.pi_concat_len); memcpy(p, &n, 2); p += 2;// 2
    memcpy(p, pkt->h.pi_concat, pkt->h.pi_concat_len); p += pkt->h.pi_concat_len; //320
    n = htons(pkt->h.dst_s_len); memcpy(p, &n, 2); p += 2;// 2
    memcpy(p, pkt->h.dst_s, pkt->h.dst_s_len); p += pkt->h.dst_s_len;//64
    // printf("(%zu bytes)\n", (size_t)(p - l2 - off));
    // ペイロード
    // printf("(%zu bytes)\n", pkt->p.tau_len);
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN; //32
    memcpy(p, pkt->p.rand_val, sizeof(pkt->p.rand_val)); p += sizeof(pkt->p.rand_val); // 4

    return (size_t)(p - l2 - off);
}

// DATA_TRANS を書く
static size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    uint16_t ctlen = (uint16_t)pkt->p.ct_len;
    size_t need = off + overlay_header_footprint() + IV_LEN + 2 + ctlen + TAG_LEN;
    if (cap < need) die("cap too small (data trans)");
    unsigned char *p = l2 + off;
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    memcpy(p, pkt->h.dest, 4); p += 4;
    memcpy(p, pkt->p.iv, IV_LEN); p += IV_LEN;
    uint16_t n = htons(ctlen); memcpy(p, &n, 2); p += 2;
    memcpy(p, pkt->p.ct, ctlen); p += ctlen;
    memcpy(p, pkt->p.tag, TAG_LEN); p += TAG_LEN;
    return (size_t)(p - l2 - off);
}

int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // 初期化
    Node nodes[NODES];
    node_init(&nodes[0], 0, "C(R0)");
    nodes[0].dh_sk = gen_x25519_keypair();
    for (int i=1;i<NODES-1;i++) {
        char n_name[8];
        snprintf(n_name, sizeof(n_name), "R%d", i);
        node_init(&nodes[i], i, n_name);
        // printf("%s\n", nodes[i].name);
    }
    char s_name[8];
    snprintf(s_name, sizeof(s_name), "S(R%d)", NODES-1);
    node_init(&nodes[NODES-1], NODES-1, s_name);
    nodes[NODES-1].dh_sk = gen_x25519_keypair();

    // 最終目的地(dest)はS
    unsigned char dest_addr[4];
    memcpy(dest_addr, nodes[NODES-1].addr, 4);

    unsigned char *tau;
    size_t tau_len = SIG_LEN;
    unsigned char *pi;
    size_t pi_len = SIG_LEN;
    unsigned char *tau2;
    size_t tau2_len = SIG_LEN;

    // 入力データの初期化
    size_t m_len;
    unsigned char *m = NULL;// τi-1検証用のデータ
    size_t n_len;
    unsigned char *n = NULL;// πi署名用のデータ
    size_t m2_len;
    unsigned char *m2 = NULL;// τ署名用のデータ

    printf("======= 経路設定フェーズ =======");
    // ==往路==
    printf("\n===============================往路=================================");
    // クライアントCの処理
    printf("\n=== Node C(R0) ===\n");
    // 往路の経路設定パケット作成
    Packet pkt; memset(&pkt, 0, sizeof(pkt));

    // k_C 公開鍵取り出し & SID=H(k_C)
    unsigned char kC_pub[PUB_LEN];
    get_raw_pub(nodes[0].dh_sk, kC_pub);
    hash_sid_from_pub(kC_pub, pkt.h.sid);
    print_hex("SID(C)=H(kC)", pkt.h.sid, SID_LEN);
    pkt.h.status = SETUP_REQ;
    memcpy(pkt.h.dest, dest_addr, 4);
    memcpy(pkt.p.peer_pub, kC_pub, PUB_LEN); // P に k_C を格納

    m = concat2(pkt.h.sid, sizeof(pkt.h.sid)-1, nodes[0].addr, strlen((char*)nodes[0].addr), &m_len);
    sign_data(nodes[0].sk, m, m_len, &tau, &tau_len);
    //パケットにτを格納
    memcpy(pkt.p.tau, tau, tau_len);
    pkt.p.tau_len = tau_len;
    print_hex("τ0", tau, tau_len);
    // pkt.h.pi_concat_len = 0;

    // 状態保存（prev=0, next=1 or self）
    state_set(&nodes[0], pkt.h.sid, -1, nodes[1].id, pkt.p.tau, SIG_LEN);

    // ==== メモリ上に L2/L3 + overlay(SETUP_REQ) を構築（送信用）====
    // 往路の送信フレームを作成
    unsigned char frame[MAX_PKT]; memset(frame, 0, sizeof(frame));
    size_t l3end = write_l2l3_min(frame, sizeof(frame));
    (void)l3end;
    size_t wire_len = build_overlay_setup_req(frame, sizeof(frame), &pkt);
    // SIDI(37) + 
    printf("C sending SETUP_REQ (%zu bytes)\n", wire_len);

    // printf("C sending SETUP_REQ\n");

    // 各ノードの処理
    for (int i = 1; i < NODES; i++) {
        printf("\n=== Node R%d ===\n", i);
        Node *me = &nodes[i];
        if (pkt.h.status != SETUP_REQ) {
            die("unexpected status on forward");
        }
        unsigned char sid_chk[SID_LEN];
        hash_sid_from_pub(pkt.p.peer_pub, sid_chk);
        if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
            die("SID verify failed");
        }

        // 次ホップを決定（直線：最後のノード以外は +1）
        // ****本来はdestに基づいて経路設定****
        int next_addr = (nodes[i].id < NODES-1) ? (nodes[i+1].id) : nodes[i].id;
        //前ホップを決定
        // const unsigned char* 
        int prev_addr = nodes[i-1].id;

        // 前ノードの τ_{i-1} を検証
        m = concat2(pkt.h.sid, sizeof(pkt.h.sid)-1, nodes[i-1].addr, strlen((char*)nodes[i-1].addr), &m_len);
        // print_hex("m = sid||R", m, m_len);
        if (!verify_sig(nodes[i-1].pk, m, m_len, pkt.p.tau, pkt.p.tau_len)) {
            printf("Verify τ%d failed\n", i-1);
            return EXIT_FAILURE;
        }
        printf("Verify τ%d success\n", i-1);
        free(m);
        // π_i = Sign(sk_i, τ_{i-1} || r_i)
        n = concat2(pkt.p.tau, pkt.p.tau_len, nodes[i].rand_val, sizeof(nodes[i].rand_val), &n_len);
        sign_data(nodes[i].sk, n, n_len, &pi, &pi_len);
        pkt.h.pi_concat = realloc(pkt.h.pi_concat, pkt.h.pi_concat_len + pi_len);
        memcpy(pkt.h.pi_concat + pkt.h.pi_concat_len, pi, pi_len);
        pkt.h.pi_concat_len += pi_len;
        printf("π%d", i);
        print_hex(" ", pi, pi_len);
        free(n);
        OPENSSL_free(pi);

        if(me->id != nodes[NODES-1].id) {
            // τ_i = Sign(sk_i, sid||R_i)
            m2 = concat2(pkt.h.sid, sizeof(pkt.h.sid)-1, nodes[i].addr, strlen((char*)nodes[i].addr), &m2_len);
            sign_data(nodes[i].sk, m2, m2_len, &tau2, &tau2_len);
            // pkt.p.tau_len = (uint16_t)tau2_len;
            memcpy(pkt.p.tau, tau2, tau2_len);
            printf("τ%d", i);
            print_hex(" ", pkt.p.tau, tau2_len);
            free(m2);
            OPENSSL_free(tau2);
        }
        // 状態保存（prev=i-1, next=i+1 or self）
        state_set(me, pkt.h.sid, prev_addr, next_addr, pkt.p.tau, tau2_len);

        // フレームを更新
        memset(frame, 0, sizeof(frame));
        (void)write_l2l3_min(frame, sizeof(frame));
        wire_len = build_overlay_setup_req(frame, sizeof(frame), &pkt);
        printf("[DEBUG] R%d built frame, wire_len=%zu\n", i, wire_len);
    }

    // サーバSの処理
    // printf("\n=== Node S(R%d) ===\n", NODES - 1);
    Node *me = &nodes[NODES-1];

    // k_S を用意して共有鍵 k を計算
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(me->dh_sk, kS_pub);

    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char shared[SEC_LEN];
    derive_shared(me->dh_sk, C_pub, shared);
    EVP_PKEY_free(C_pub);

    memcpy(me->sess_key, shared, KEY_LEN);
    me->has_sess = 1;
    print_hex("S derived k", me->sess_key, KEY_LEN);

    printf("\n===============================復路=================================");
    // サーバSの処理
    printf("\n=== Node S(R%d) ===\n", NODES - 1);

    // ここでsidに紐づけてpi_concatを保存

    //復路の経路設定パケット作成
    pkt.h.status = SETUP_RESP;
    // DST_S = Sign(skS, pi_concat)
    unsigned char *SigS = NULL;
    size_t SigS_len = 0;
    sign_data(nodes[NODES-1].sk, pkt.h.pi_concat, pkt.h.pi_concat_len, &SigS, &SigS_len);
    print_hex("DST_S (Double Signature Tag by S)", SigS, SigS_len);
    memcpy(pkt.h.dst_s, SigS, SigS_len);
    pkt.h.dst_s_len = SigS_len;
    memcpy(pkt.p.peer_pub, kS_pub, PUB_LEN);
    memcpy(pkt.p.rand_val, me->rand_val, sizeof(me->rand_val));

    // ==== SETUP_RESP をパケットに積む（DST_S と pi_concat を格納）====
    // 復路の送信フレームを作成
    memset(frame, 0, sizeof(frame));
    (void)write_l2l3_min(frame, sizeof(frame));
    // printf("a");
    wire_len = build_overlay_setup_resp(frame, sizeof(frame), &pkt);//, pkt.h.pi_concat, (uint16_t)pkt.h.pi_concat_len, SigS, (uint16_t)SigS_len);
    printf("S sending SETUP_RESP (%zu bytes)\n", wire_len);

    // 復路は逆順に転送
    int cur = nodes[ROUTERS].id;
    while (cur != -1) {
        printf("\n=== Node R%d ===\n", cur);
        size_t idx = cur + 1;                // π_{i+1} のインデックス
        size_t offset = (idx - 1) * SIG_LEN;
        if (offset + SIG_LEN > pkt.h.pi_concat_len) {
            die("pi_concat out of range");
        }
        // printf("offset for π%d: %zu\n", (int)idx, offset);
        unsigned char *pi_next = pkt.h.pi_concat + offset; // π_{i+1} の先頭
        size_t pi_next_len = SIG_LEN;
        // DST_Sを検証
        if (!verify_sig(nodes[NODES-1].pk, pkt.h.pi_concat, pkt.h.pi_concat_len, pkt.h.dst_s, pkt.h.dst_s_len)) {
            printf("Verify DST_S failed\n");
            return EXIT_FAILURE;
        }
        printf("Verify DST_S success\n");
        // π_i+1 を検証
        const unsigned char *tau = state_get_tau(&nodes[cur], pkt.h.sid);
        // size_t tau_len = SIG_LEN;
        n = concat2(tau, SIG_LEN, pkt.p.rand_val, sizeof(pkt.p.rand_val), &n_len);
        // print_hex("π_next", pi_next, SIG_LEN);
        if (!verify_sig(nodes[cur+1].pk, n, n_len, pi_next, pi_next_len)) {
            printf("Verify π%d failed\n", cur+1);
            return EXIT_FAILURE;
        }
        printf("Verify π%d success\n", cur+1);
        free(n);
        Node *curN = &nodes[cur];
        memcpy(pkt.p.rand_val, curN->rand_val, sizeof(curN->rand_val));//自身の乱数をセット
        // frame を再構築
        memset(frame, 0, sizeof(frame));
        (void)write_l2l3_min(frame, sizeof(frame));
        wire_len = build_overlay_setup_resp(frame, sizeof(frame), &pkt);//, pkt.h.pi_concat, (uint16_t)pkt.h.pi_concat_len, SigS, (uint16_t)SigS_len);
        int prev_addr = state_get_prev(curN, pkt.h.sid);
        cur = prev_addr;
    }

    // Cもkを計算
    EVP_PKEY *S_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char kC_shared[SEC_LEN];
    derive_shared(nodes[0].dh_sk, S_pub, kC_shared);
    EVP_PKEY_free(S_pub);

    memcpy(nodes[0].sess_key, kC_shared, KEY_LEN);
    nodes[0].has_sess = 1;
    print_hex("C derived k", nodes[0].sess_key, KEY_LEN);

    if (memcmp(nodes[0].sess_key, nodes[NODES-1].sess_key, KEY_LEN) != 0) {
        die("k mismatch");
    }
    puts("== 経路設定完了・セッション確立 ==");


    // printf("\n======= データ転送フェーズ =======\n");
    // const char *msg = "hello world";
    // size_t msg_len = strlen(msg);
    // printf("C sending plaintext: %s\n", msg);

    // // Cの処理: msgを暗号化して送信パケット作成
    // memset(&pkt, 0, sizeof(pkt));
    // unsigned char sid_use[SID_LEN];
    // get_raw_pub(nodes[0].dh_sk, kC_pub);
    // hash_sid_from_pub(kC_pub, sid_use);
    // memcpy(pkt.h.sid, sid_use, SID_LEN);

    // pkt.h.status = DATA_TRANS;
    // memcpy(pkt.h.dest, dest_addr, 4);

    // aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    // pkt.p.ct_len = msg_len;

    // // ==== DATA_TRANS をパケットに積む ====
    // memset(frame, 0, sizeof(frame));
    // (void)write_l2l3_min(frame, sizeof(frame));
    // wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);

    // // 各ノードの処理: state.next で転送
    // cur = nodes[0].id;
    // while (cur != NODES-1) {
    //     Node *me = &nodes[cur];
    //     // printf("%s forwarding packet...\n", me->name);
    //     printf("%s -> ", me->name);
    //     int next_addr = state_get_next(me, pkt.h.sid);
    //     if (next_addr < 0) {
    //         die("no next hop in data forward");
    //     }
    //     cur = next_addr;
    // }
    // puts("");
    // // Sの処理: 復号
    // unsigned char plain[MAX_PTXT];
    // if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain))
    //     die("GCM auth fail at S");
    // printf("%s got plaintext: %.*s\n", nodes[NODES-1].name, (int)pkt.p.ct_len, plain);

    // 後処理
    for (int i=0;i<NODES;i++) {
        node_free(&nodes[i]);
    }
    if (tau) OPENSSL_free(tau);
    if (pi) OPENSSL_free(pi);
    if (tau2) OPENSSL_free(tau2);
    if (SigS) OPENSSL_free(SigS);

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}