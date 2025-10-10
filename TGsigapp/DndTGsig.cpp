#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <zlib.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <iostream>
#include <limits.h>
#include <ctime>
#include <fstream>
#include <vector>

#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/crl.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#define ROUTERS 4
#define NODES   (ROUTERS+2)

#define ETH_LEN 14     // VLAN 無し
#define IP_LEN  20
#define SID_LEN 32
#define CID_LEN 2
#define PUB_LEN 32
#define SEC_LEN 32
#define KEY_LEN 32
#define SEG_LEN 12  // c_i の長さ（固定長にする）
#define TAG_LEN 16
#define IV_LEN  12
#define MAX_SEG_CON (ROUTERS + 1) * (SEG_LEN + TAG_LEN + IV_LEN)
#define SIG_LEN 64
#define MAX_PI ((ROUTERS + 1) * SIG_LEN)
#define MAX_PTXT 1024
#define MAX_PKT  2048
#define MAX_STATE  8

typedef enum { SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;
 
// ポリシー
const char *policy[] = {"attack", "leak", "bomb", "hello"};
const int POLICY_COUNT = sizeof(policy) / sizeof(policy[0]);

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
// SID(32) | CID(2) | STATUS(1) | idx(1)
typedef struct {
    unsigned char sid[SID_LEN];  // セッションID
    unsigned char cid[CID_LEN];      // サーキットID
    uint8_t status;              // ステータス (SETUP_REQ, SETUP_RESP, DATA_TRANS)
    uint8_t idx;                 // ルータインデックス (0=センダー, NODES-1=レシーバ)
    // unsigned char dest[4];       // 宛先アドレス

    // SETUP_REQ
    unsigned char seg_concat[MAX_SEG_CON];         // 暗号化経路情報リストデータ
    // SETUP_REQ / SETUP_RESP ヘッダ: πリスト情報
    unsigned char pi_concat[MAX_PI];         // π リストデータ

    // SETUP_RESP ヘッダ: ρ
    unsigned char rho[2][SIG_LEN];             // ρ データ

} Oheader;

// ---- ペイロード ----
typedef struct {
    
    // SETUP_REQ
    // uint16_t tau_len;
    unsigned char tau[SIG_LEN];       //検証用の署名
    
    // SETUP_RESP
    unsigned char rand_val[4];        //検証用の乱数
    
    // ---- SETUP_REQ / SETUP_RESP ----
    unsigned char peer_pub[PUB_LEN];  // 公開鍵 (k_C または k_S)

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
    int id; // ノードID (今回は便宜上0=センダー, NODES-1=レシーバ)
    // char name[8];
    unsigned char addr[4];
    unsigned char rand_val[4];


    // X25519 (DH)
    EVP_PKEY *dh_sk;
    EVP_PKEY *dh_pk;

    // X25519鍵
    EVP_PKEY *sk;
    EVP_PKEY *pk;

    // セッション鍵
    //センダーは全ノード分、レシーバは自ノード分のみ
    unsigned char k[NODES][KEY_LEN];//各ノードとの共有鍵
    unsigned char ki[KEY_LEN];

    unsigned char sess_key[KEY_LEN];
    int has_sess;

    // SIDに紐づく前後ホップ状態
    struct {
        int used;
        unsigned char sid[SID_LEN];
        unsigned char precid[CID_LEN]; // サーキットID
        unsigned char nexcid[CID_LEN]; // サーキットID
        char prev_addr; //本来アドレスだが便宜上ノードID
        char next_addr; //本来アドレスだが便宜上ノードID
        char nnext_addr; //本来アドレスだが便宜上ノードID
        unsigned char tau[SIG_LEN];   // τi
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

// DH秘密鍵から公開鍵を取得
static void get_raw_pub(const EVP_PKEY *pkey, unsigned char pub[PUB_LEN]) {
    size_t len = PUB_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0 || len != PUB_LEN) die("get_raw_public_key");
}

// 公開鍵のインポート
static EVP_PKEY* import_x25519_pub(const unsigned char *pub) {
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, PUB_LEN);
    if (!p) die("new_raw_public_key");
    return p;
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

static unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen) {
    *outlen = alen + blen;
    unsigned char *buf = (unsigned char*)malloc(*outlen);
    if (!buf) die("malloc failed");
    memcpy(buf, a, alen);
    memcpy(buf + alen, b, blen);
    return buf;
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
static void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) <= 0)
        die_ossl("EVP_DigestSignInit");
    if (EVP_DigestSign(mdctx, sig, siglen, data, datalen) <= 0)
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
static void node_init(Node *node, int id){//, const char *name) {
    memset(node, 0, sizeof(Node));
    // snprintf(node->name, sizeof(node->name), "%s", name);
    node->id = id;
    node->sk = gen_ed25519_keypair();
    node->pk = extract_public_only(node->sk);
    node->dh_sk = gen_x25519_keypair();//ここでファイル読み込みしたい
    unsigned char pub[PUB_LEN];
    get_raw_pub(node->dh_sk, pub);
    node->dh_pk = import_x25519_pub(pub);
    // RAND_bytes(node->addr, sizeof(node->addr));
    // アドレスをしっかり設定
    node->addr[0] = 192; node->addr[1] = 168;
    node->addr[2] = 10;  node->addr[3] = (uint8_t)id;
    // printf("addr: %d.%d.%d.%d\n", node->addr[0], node->addr[1], node->addr[2], node->addr[3]);
    RAND_bytes(node->rand_val, sizeof(node->rand_val));
}

static void node_free(Node *n) {
    if (n->dh_sk) EVP_PKEY_free(n->dh_sk);
    if (n->sk) EVP_PKEY_free(n->sk);
    if (n->pk) EVP_PKEY_free(n->pk);
}

// ステート操作
static void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char precid[CID_LEN], unsigned char nexcid[CID_LEN], unsigned char prev_addr, int next_addr, int nnext_addr, const unsigned char *tau, size_t tau_len) {
    for (int i=0;i<MAX_STATE;i++) {
        if (!n->state[i].used) {
            n->state[i].used = 1;
            memcpy(n->state[i].sid, sid, SID_LEN);
            memcpy(n->state[i].precid, precid, CID_LEN);
            memcpy(n->state[i].nexcid, nexcid, CID_LEN);
            n->state[i].prev_addr = prev_addr;
            n->state[i].next_addr = next_addr;
            n->state[i].nnext_addr = nnext_addr;
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
static size_t overlay_header_footprint(void) { return SID_LEN + CID_LEN + 1 + 1 + 4; }//固定へッダ長

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
    size_t need = off + overlay_header_footprint() + (pkt->h.idx - 1) * SIG_LEN + SIG_LEN + PUB_LEN;
    if (cap < need) die("cap too small (setup req)");
    unsigned char *p = l2 + off; //現在の位置 ＋ L2L3オフセット
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, pkt->h.cid, CID_LEN); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // print_hex("pkt.h.sid", pkt->h.sid, SID_LEN);

    // seg_concatを乗せる
    memcpy(p, pkt->h.seg_concat, MAX_SEG_CON); p += MAX_SEG_CON; // segリストは固定長
    memcpy(p, pkt->h.pi_concat, (pkt->h.idx - 1) * SIG_LEN); p += (pkt->h.idx - 1) * SIG_LEN; // πリストは固定長

    // ぺイロード
    memcpy(p, pkt->p.tau, SIG_LEN); p += SIG_LEN; //固定長で送る
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN;
    return (size_t)(p - l2 - off); // 書き終わったバイト位置
}

// SETUP_RESP を書く（DST_S/πリスト付き）
static size_t build_overlay_setup_resp(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    size_t need = off + overlay_header_footprint() + MAX_PI + SIG_LEN + 4 + PUB_LEN;
    if (cap < need) die("cap too small (setup resp)");
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, pkt->h.cid, CID_LEN); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // printf("R%d\n", pkt->h.idx);
    memcpy(p, pkt->h.pi_concat, MAX_PI); p += MAX_PI; //固定長で送る
    memcpy(p, pkt->h.rho, SIG_LEN * 2); p += SIG_LEN * 2; //固定長で送る
    // print_hex("rho", pkt->h.rho, SIG_LEN*2);
    // ペイロード
    memcpy(p, pkt->p.rand_val, sizeof(pkt->p.rand_val)); p += sizeof(pkt->p.rand_val); // 4
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN; //32

    return (size_t)(p - l2 - off);
}

// DATA_TRANS を書く
static size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    uint16_t ctlen = (uint16_t)pkt->p.ct_len;
    size_t need = off + overlay_header_footprint() + IV_LEN + 2 + ctlen + TAG_LEN;
    if (cap < need) die("cap too small (data trans)");
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, &pkt->h.cid, 1); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // ぺイロード
    memcpy(p, pkt->p.iv, IV_LEN); p += IV_LEN;
    uint16_t n = htons(ctlen); memcpy(p, &n, 2); p += 2;
    memcpy(p, pkt->p.ct, ctlen); p += ctlen;
    memcpy(p, pkt->p.tag, TAG_LEN); p += TAG_LEN;
    return (size_t)(p - l2 - off);
}

// フレームからパケットをパース
static int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt) {
    // L2/L3を読み飛ばす
    size_t l3end = 34;//read_l2l3_min(frame, frame_len);
    if (l3end == 0) return -1;
    const unsigned char *buf = frame + l3end;
    const unsigned char *p = buf;
    size_t len = frame_len - l3end;
    if (len < SID_LEN + 1 + 4) return -1; // sid + status + dest
    
    //固定ヘッダ
    memcpy(pkt->h.sid, p, SID_LEN); p += SID_LEN;
    memcpy(pkt->h.cid, p, CID_LEN); p += CID_LEN;
    pkt->h.status = *p++;
    pkt->h.idx = *p++;
    
    if (pkt->h.status == SETUP_REQ) {
        // seg_listをパース
        if (p + MAX_SEG_CON > buf + len) return -1;
        memcpy(pkt->h.seg_concat, p, MAX_SEG_CON); // segリストは固定長で受け取る
        p += MAX_SEG_CON;
        //π_list
        if (p + (pkt->h.idx - 1) * SIG_LEN > buf + len) return -1;
        memcpy(pkt->h.pi_concat, p, (pkt->h.idx - 1) * SIG_LEN); // πリストはidxによる可変長で受け取る
        p += (pkt->h.idx - 1) * SIG_LEN;

        //  τ + peer_pub
        if (p + SIG_LEN > buf + len) return -1;
        memcpy(pkt->p.tau, p, SIG_LEN); p += SIG_LEN;
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;

    } else if (pkt->h.status == SETUP_RESP) {
        // π_list
        if (p + MAX_PI > buf + len) return -1;
        memcpy(pkt->h.pi_concat, p, MAX_PI); //πリストは固定長で受け取る
        p += MAX_PI;

        // ρ
        if (p + SIG_LEN * 2 > buf + len) return -1;
        memcpy(pkt->h.rho, p, SIG_LEN * 2); p += SIG_LEN * 2;
        // print_hex("rho", pkt->h.rho, SIG_LEN*2);

        // rand_val + peer_pub
        if (p + 4 > buf + len) return -1;
        memcpy(pkt->p.rand_val, p, 4); p += 4;
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
    } else if (pkt->h.status == DATA_TRANS) {
        // payload: IV + CT_LEN + CT + TAG
        if (p + 12 > buf + len) return -1;
        memcpy(pkt->p.iv, p, 12); p += 12;
        pkt->p.ct_len = ntohs(*(uint16_t*)p); p += 2;
        if (p + pkt->p.ct_len > buf + len) return -1;
        memcpy(pkt->p.ct, p, pkt->p.ct_len); p += pkt->p.ct_len;
        if (p + 16 > buf + len) return -1;
        memcpy(pkt->p.tag, p, 16); p += 16;
    } else {
        return -1; // 未知のステータス
    }
    return 0;
}

// ルータ処理（SETUP_REQの中継）
static int router_handle_forward(unsigned char *frame, size_t frame_cap, Node *nodes) {
    Packet pkt;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    size_t m_len, n_len, m2_len;
    unsigned char *m = NULL, *n = NULL, *m2 = NULL;
    unsigned char pi[SIG_LEN], tau[SIG_LEN];
    size_t pi_len = SIG_LEN, tau_len = SIG_LEN;

    if (pkt.h.status != SETUP_REQ) { fprintf(stderr,"unexpected status\n"); return -1; }

    unsigned char sid_chk[SID_LEN];
    hash_sid_from_pub(pkt.p.peer_pub, sid_chk);
    if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
        fprintf(stderr,"SID verify failed at R%d\n", idx);
        return -1;
    }

    unsigned char precid[CID_LEN]; 
    memcpy(precid, pkt.h.cid, CID_LEN);
    // 新しいサーキットIDをランダム生成
    RAND_bytes(pkt.h.cid, CID_LEN);

    // 経路情報復号
    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char sharec[SEC_LEN];
    derive_shared(me->dh_sk, C_pub, sharec);
    memcpy(me->ki, sharec, KEY_LEN);
    // print_hex("ki", me->ki, KEY_LEN);

    size_t segoff = (me->id - 1) * (SEG_LEN + TAG_LEN + IV_LEN);
    const unsigned char *ci  = pkt.h.seg_concat + segoff;
    // print_hex("ci", ci, SEG_LEN);
    const unsigned char *tag = pkt.h.seg_concat + segoff + SEG_LEN;
    // print_hex("tag", tag, TAG_LEN);
    const unsigned char *iv  = pkt.h.seg_concat + segoff + SEG_LEN + TAG_LEN;
    // print_hex("iv", iv, IV_LEN);

    // 共有鍵 k_i で復号
    unsigned char plain[12];  // 復号結果を格納（12バイト＋α）
    if (!aead_decrypt(me->ki, ci, SEG_LEN, pkt.h.sid, iv, tag, plain))
        die("GCM auth fail (seg decrypt)");
    // printf("got plaintext: %s\n", plain);
    // print_hex("Decrypted segment", plain, 12);
    
    //復号結果を分割
    // 結果を分割: IPv4アドレス3つ分 (各4バイト)
    unsigned char prev_addr[4], next_addr[4], nnext_addr[4];
    memcpy(prev_addr,  plain,     4);
    memcpy(next_addr,  plain + 4, 4);
    memcpy(nnext_addr, plain + 8, 4);
    // printf("prev_addr: %u.%u.%u.%u\n", prev_addr[0], prev_addr[1], prev_addr[2], prev_addr[3]);
    // printf("next_addr: %u.%u.%u.%u\n", next_addr[0], next_addr[1], next_addr[2], next_addr[3]);
    // printf("nnext_addr: %u.%u.%u.%u\n", nnext_addr[0], nnext_addr[1], nnext_addr[2], nnext_addr[3]);


    //******アドレスからidxを引く
    int prev_idx = prev_addr[3];//get_node_idx(prev_addr, nodes);
    int next_idx = next_addr[3];//get_node_idx(next_addr, nodes);
    int nnext_idx = nnext_addr[3];//get_node_idx(nnext_addr, nodes);

    // 前ノードの τ_{i-1} を検証
    m = concat2(pkt.h.sid, SID_LEN, nodes[prev_idx].addr, sizeof(nodes[prev_idx].addr), &m_len);
    if (!verify_sig(nodes[prev_idx].pk, m, m_len, pkt.p.tau, SIG_LEN)) {//pkt.p.tau_len)) {
        fprintf(stderr, "Verify τ%d failed\n", prev_idx);
        free(m);
        return -1;
    }
    printf("Verify τ%d success\n", prev_idx);
    free(m);

    // π_i = Sign(sk_i, τ_{i-1} || r_i)
    n = concat2(pkt.p.tau, SIG_LEN, me->rand_val, sizeof(me->rand_val), &n_len);
    sign_data(me->sk, n, n_len, pi, &pi_len);
    free(n);
    size_t offset = (idx - 1) * SIG_LEN;

    // if (pkt.h.pi_concat_len + pi_len > sizeof(pkt.h.pi_concat)) {
    if (offset + pi_len > sizeof(pkt.h.pi_concat)) {
        fprintf(stderr,"pi_concat overflow at R%d\n", idx);
        // OPENSSL_free(pi);
        return -1;
    }
    memcpy(pkt.h.pi_concat + offset, pi, pi_len);
    // printf("π%d", idx);print_hex(" ", pi, pi_len);
    // OPENSSL_free(pi);

    // τ_i = Sign(sk_i, sid||addr) (サーバは除く)
    if (me->id != NODES-1) {
        m2 = concat2(pkt.h.sid, SID_LEN, me->addr, sizeof(me->addr), &m2_len);
        sign_data(me->sk, m2, m2_len, tau, &tau_len);
        free(m2);
        if (tau_len > SIG_LEN) { 
            // OPENSSL_free(tau); 
            fprintf(stderr,"tau_len too big\n"); return -1; }
        memcpy(pkt.p.tau, tau, tau_len);
        // printf("τ%d", idx); print_hex(" ", pkt->p.tau, pkt->p.tau_len);
        // OPENSSL_free(tau);

    }

    // 次のノードの位置を設定
    pkt.h.idx++;

    // ステート保存（prev=前ホップアドレス, next=次ホップアドレス or 自身）
    state_set(me, pkt.h.sid, precid, pkt.h.cid, prev_idx, next_idx, nnext_idx, pkt.p.tau, SIG_LEN);

    // フレーム再構築
    size_t wire_len = build_overlay_setup_req(frame, frame_cap, &pkt);
    printf("Forward frame wire_len=%zu pi_list_len=%u\n", wire_len, idx * SIG_LEN);
    return 0;
}

// ルータ処理（SETUP_RESPの中継）
static int router_handle_reverse(unsigned char *frame, size_t frame_cap, Node *nodes) {
    Packet pkt;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];

    if (pkt.h.status != SETUP_RESP) { fprintf(stderr,"unexpected status\n"); return -1; }

    unsigned char precid[CID_LEN];
    memcpy(precid, pkt.h.cid, CID_LEN);
    if (memcmp(precid, me->state[0].nexcid, CID_LEN) != 0) {// 最初のステートだけ見てサーキットIDを比較
        fprintf(stderr,"Circuit ID mismatch\n");
        return -1;
    }

    unsigned char rho[SIG_LEN];
    // ρ_i+2を検証
    if (idx + 2 <= NODES - 1) {
        if (idx % 2 == 0) {
            memcpy(rho, pkt.h.rho[0], SIG_LEN);
        } else {
            memcpy(rho, pkt.h.rho[1], SIG_LEN);
        }
        size_t n_len;
        unsigned char *n = NULL;
        n = concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &n_len);
        // print_hex("n", n, n_len);
        // print_hex("rho to verify", rho, SIG_LEN);
        if (!verify_sig(nodes[idx + 2].pk, n, n_len, rho, SIG_LEN)) {
            fprintf(stderr,"Verify ρ%d failed\n", idx + 2);
            free(n);
            return -1;
        }
        printf("Verify ρ%d success\n", idx + 2);
    }

    // π_i+1 を取り出す
    size_t nidx = idx + 1;
    if (nidx == 0) { fprintf(stderr,"invalid nidx\n"); return -1; }
    size_t offset = (nidx - 1) * SIG_LEN;
    // if (offset + SIG_LEN > pkt.h.pi_concat_len) { 
    if (offset + SIG_LEN > MAX_PI) { 
        fprintf(stderr,"pi_concat out of range\n"); 
        return -1; 
    }
    unsigned char *pi_next = pkt.h.pi_concat + offset;

    // τ_i を取り出す
    const unsigned char *tau = state_get_tau(me, pkt.h.sid);
    if (!tau) { fprintf(stderr,"tau not found at R%d\n", idx); return -1; }

    // π_i+1 を検証
    size_t n_len;
    unsigned char *n = concat2(tau, SIG_LEN, pkt.p.rand_val, sizeof(pkt.p.rand_val), &n_len);
    if (!verify_sig(nodes[nidx].pk, n, n_len, pi_next, SIG_LEN)) {
        free(n); 
        fprintf(stderr,"Verify π%ld failed at R%d\n", nidx, idx); 
        return -1;
    }
    free(n);
    printf("Verify π%ld success \n", nidx);

    if (idx - 2 >= 0) {
        // ρ_iを生成
        size_t m_len, rho_len;
        unsigned char *m = NULL;
        m = concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &m_len);
        sign_data(me->sk, m, m_len, pkt.h.rho[idx % 2], &rho_len);
        free(m);
        // print_hex("ρ", pkt.h.rho, SIG_LEN*2);
    }
    

    pkt.h.idx--;

    // フレーム再構築(乱数を更新)
    memcpy(pkt.h.cid, me->state[0].precid, CID_LEN);
    memcpy(pkt.p.rand_val, me->rand_val, sizeof(me->rand_val));
    size_t wire_len = build_overlay_setup_resp(frame, frame_cap, &pkt);
    printf("Reverse frame wire_len=%zu rand_val updated\n", wire_len);
    return 0;
}

// 鍵をファイルに保存
int save_key_to_file(const char *path, groupsig_key_t *key,
                     int (*export_func)(byte_t **, uint32_t *, groupsig_key_t *)) {
    byte_t *bytes = NULL;
    uint32_t size = 0;

    if (export_func(&bytes, &size, key) != IOK) {
        fprintf(stderr, "Key export failed: %s\n", path);
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        free(bytes);
        return -1;
    }

    fwrite(bytes, 1, size, f);
    fclose(f);
    free(bytes);
    return 0;
}

// 鍵をファイルから読み込み
groupsig_key_t *load_key_from_file(const char *path, uint8_t scheme,
                                   groupsig_key_t *(*import_func)(uint8_t, byte_t *, uint32_t)) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    byte_t *buf = (byte_t *)malloc(len);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    fread(buf, 1, len, f);
    fclose(f);

    groupsig_key_t *key = import_func(scheme, buf, len);
    free(buf);
    return key;
}

int apply_policy_contract(const char *msg) {
    if (!msg) return 0;
    for (int i = 0; i < POLICY_COUNT; i++) {
        if (strstr(msg, policy[i]) != NULL) {
            // 禁止ワード表示(英語で)
            printf("Detected: '%s'\n", policy[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    RAND_load_file("/dev/urandom", 32);

    // 初期化
    Node nodes[NODES];
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i);
    }
    // node_init(&nodes[NODES-1], NODES-1);
    // nodes[0].dh_sk = gen_x25519_keypair();
    // nodes[NODES-1].dh_sk = gen_x25519_keypair();

    // τ0用のデータ
    unsigned char tau[SIG_LEN];
    size_t tau_len = SIG_LEN;
    size_t m_len;
    unsigned char *m = NULL;

    printf("======= 経路設定フェーズ =======");
    printf("\n===============================往路=================================");
    // センダーSの処理
    printf("\n=== Node S(R0) ===\n");
    Packet pkt; 
    // k_C 公開鍵取り出し & SID=H(k_C)
    unsigned char kC_pub[PUB_LEN];
    int idx = 0;
    Node *me = &nodes[idx];
    get_raw_pub(me->dh_sk, kC_pub);
    // print_hex("kC_pub", kC_pub, PUB_LEN);
    //グループ署名生成
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);

    // message_t *gsm = message_from_string((char *)kC_pub);
    message_t *gsm = message_from_bytes(kC_pub, PUB_LEN);
    // print_hex("gsm", gsm->bytes, gsm->length);
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
    groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);

    // --- 署名をバイナリにエクスポート ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    printf("Exported signature length: %u bytes\n", sig_size);
    
   
    size_t sid_len;
    unsigned char *sid = concat2(kC_pub, PUB_LEN, sig_bytes, sig_size, &sid_len);
    // print_hex("sid", sid, sid_len);
    hash_sid_from_pub(sid, pkt.h.sid);
    print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
    // サーキットIDを生成
    RAND_bytes(pkt.h.cid, CID_LEN);
    pkt.h.status = SETUP_REQ;

    // 各ノードの共有鍵 k_i を計算 & c_i を生成
    unsigned char sharenode[SEC_LEN];
    for (int i = 1; i < NODES; i++) {
        derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
        memcpy(me->k[i], sharenode, KEY_LEN);
        // print_hex("ki", me->k[i], KEY_LEN);

        // 前後ホップ (例: prev=i-1, next=i+1)
        unsigned char *prehop  = nodes[i-1].addr;
        unsigned char *nexthop = (i == NODES - 1) ? nodes[i].addr : nodes[i+1].addr;
        unsigned char *nnexthop = (i >= NODES - 2) ? nodes[i].addr : nodes[i+2].addr;
        // printf("nnexthop: %d.%d.%d.%d\n", nnexthop[0], nnexthop[1], nnexthop[2], nnexthop[3]);

        size_t p_len;
        unsigned char *p = concat2(prehop, 4, nexthop, 4, &p_len);
        size_t ap_len;
        unsigned char *ap = concat2(p, p_len, nnexthop, 4, &ap_len);
        
        unsigned char ci[SEG_LEN];
        unsigned char iv[IV_LEN], tag[TAG_LEN];//, ci[SEG_LEN];
        aead_encrypt(me->k[i], ap, ap_len, pkt.h.sid, iv, ci, tag);
        // // リングバッファもどき(容量=ROUTERS)に c_iやタグを循環的に挿入
        size_t offset = (size_t)((i-1) % (ROUTERS + 1)) * (SEG_LEN + TAG_LEN + IV_LEN);//ROUTERS + 1では経路長が漏洩するため適切な固定長(12など)にする
        // print_hex("c_i||tag_i||iv_i", t2, t2_len);

        // memcpy(pkt.h.seg_concat + offset, t2, t2_len);
        // printf("offset=%zu\n", offset);
        memcpy(pkt.h.seg_concat + offset, ci, SEG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN, tag, TAG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN + TAG_LEN, iv, IV_LEN);
        free(p);  free(ap);
        // free(t1); free(t2);
    }

    // print_hex("seg_concat", pkt.h.seg_concat, (ROUTERS + 1) * (SEG_LEN + TAG_LEN + IV_LEN));
    // τ_0 = Sign(sk_0, sid || addr_C)を生成
    // unsigned char *k = NULL;
    m = concat2(pkt.h.sid, SID_LEN, nodes[idx].addr, sizeof(nodes[idx].addr), &m_len);
    sign_data(nodes[idx].sk, m, m_len, tau, &tau_len);
    free(m);

    //パケットにτを格納
    memcpy(pkt.p.tau, tau, tau_len);
    // print_hex("τ0", tau, tau_len);
    memcpy(pkt.p.peer_pub, kC_pub, PUB_LEN); // P に k_C を格納

    // 状態保存（prev=0, next=1 or self）
    unsigned char precid[CID_LEN];
    //前のサーキットがないので0クリア
    memset(precid, 0, CID_LEN);
    state_set(&nodes[idx], pkt.h.sid, precid, pkt.h.cid, -1, nodes[idx + 1].id, nodes[idx + 2].id, pkt.p.tau, SIG_LEN);

    // 次のノードの位置を設定
    pkt.h.idx = 1;

    // ==== メモリに L2/L3 + overlay(SETUP_REQ) を構築（送信用）====
    // 往路の送信フレームを作成
    unsigned char frame[MAX_PKT]; 
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    size_t wire_len = build_overlay_setup_req(frame, sizeof(frame), &pkt);
    // SID(36) + seg_list(40*5) + πリスト(0) + peer_pub(32) + τ(64) = 332B
    printf("S sending SETUP_REQ (%zu bytes)\n", wire_len);

    // 各ノードの処理
    for (int i = 1; i < NODES; i++) {
        if (router_handle_forward(frame, sizeof(frame), nodes) != 0) die("forward fail");
    }

    // レシーバRの処理
    // printf("\n=== Node R(R%d) ===\n", NODES - 1);
    me = &nodes[NODES-1];

    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "R: parse failed\n");
        return -1;
    }

    //　グループ署名の検証
    // 検証側
    unsigned char *decompressed = NULL;
    // decompress_zlib(compressed, compressed_len, &decompressed, sig_size);
    printf("Decompressed: %u / %u bytes\n", sig_size, sig_size);

    uint8_t valid;
    message_t *ppp = message_from_bytes(pkt.p.peer_pub, PUB_LEN);
    groupsig_verify(&valid, sig, ppp, grpkey);
    printf("TGsig verification: %s\n", valid ? "valid" : "invalid");

    // Rもkを計算
    EVP_PKEY *S_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char shared[SEC_LEN];
    derive_shared(me->dh_sk, S_pub, shared);
    EVP_PKEY_free(S_pub);
    memcpy(me->sess_key, shared, KEY_LEN);
    me->has_sess = 1;
    print_hex("R derived k", me->sess_key, KEY_LEN);
    
    printf("\n===============================復路=================================");
    // レシーバRの処理
    printf("\n=== Node R(R%d) ===\n", NODES - 1);
    
    // ここでsidに紐づけてpi_concatを保存
    
    //復路の経路設定パケット作成
    memcpy(pkt.h.cid, me->state[0].precid, CID_LEN); // 往路の最後のサーキットIDを流用
    pkt.h.status = SETUP_RESP;
    pkt.h.idx--;
    pkt.h.idx--; // pi_concatサイズ計算のため加算しすぎたidxをもどす
    
    // ρ_sを生成
    size_t rho_len = SIG_LEN;
    unsigned char rho[SIG_LEN];
    m = concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &m_len);
    // print_hex("m for rho", m, m_len);
    sign_data(me->sk, m, m_len, rho, &rho_len);
    free(m);
    memcpy(pkt.h.rho[(pkt.h.idx + 1) % 2], rho, SIG_LEN); // ρリストは2つ分だけ保持
    // print_hex("ρ", pkt.h.rho, SIG_LEN*2);

    // k_R を用意
    unsigned char kR_pub[PUB_LEN];
    get_raw_pub(me->dh_sk, kR_pub);
    memcpy(pkt.p.peer_pub, kR_pub, PUB_LEN);
    memcpy(pkt.p.rand_val, me->rand_val, sizeof(me->rand_val));

    // ==== SETUP_RESP をパケットに積む（DST_S と pi_concat を格納）====
    // 復路の送信フレームを作成
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    // print_hex("SID(R)", pkt.h.sid, SID_LEN);
    wire_len = build_overlay_setup_resp(frame, sizeof(frame), &pkt);
    printf("R sending SETUP_RESP (%zu bytes)\n", wire_len);

    // 各ノードの処理
    // 復路は逆順に転送
    // int cur = nodes[ROUTERS].id;
    for (int i = ROUTERS; i >= 0; i--) {
        if (router_handle_reverse(frame, sizeof(frame), nodes) != 0) die("reverse fail");
        // Node *curN = &nodes[cur];
        // cur = state_get_prev(curN, pkt.h.sid);
    }

    // センダーSの処理
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "S: parse failed\n");
        // free(pkt);
        return -1;
    }
    // Sもkを計算
    me = &nodes[0];
    EVP_PKEY *R_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char kC_shared[SEC_LEN];
    derive_shared(me->dh_sk, R_pub, kC_shared);
    EVP_PKEY_free(R_pub);

    memcpy(me->sess_key, kC_shared, KEY_LEN);
    me->has_sess = 1;
    print_hex("S derived k", me->sess_key, KEY_LEN);

    // PKIから生成した鍵と同じか確認
    if (memcmp(me->sess_key, nodes[0].k[NODES-1], KEY_LEN) != 0) {
        die("k mismatch");
    }
    puts("== 経路設定完了・セッション確立 ==");

    printf("\n======= データ転送フェーズ =======\n");
    const char *msg = "hello world";
    size_t msg_len = strlen(msg);
    printf("S sending plaintext: %s\n", msg);

    // Sの処理: msgを暗号化して送信パケット作成
    unsigned char sid_use[SID_LEN];
    get_raw_pub(nodes[0].dh_sk, kC_pub);
    hash_sid_from_pub(kC_pub, sid_use);
    memcpy(pkt.h.sid, sid_use, SID_LEN);

    pkt.h.status = DATA_TRANS;

    aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = msg_len;

    // ==== DATA_TRANS をパケットに積む ====
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);

    // 各ノードの処理: state.next で転送
    int cur = nodes[0].id;
    while (cur != NODES-1) {
        Node *me = &nodes[cur];
        if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
            fprintf(stderr, "parse failed\n");
            return -1;
        }
        printf("R%d -> ", me->id);
        int next_addr = state_get_next(me, pkt.h.sid);
        if (next_addr < 0) {
            die("no next hop in data forward");
        }
        cur = next_addr;
    }
    // Rの処理: 復号
    printf("R(R%d)\n", cur);
    unsigned char plain[MAX_PTXT];
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "R: parse failed\n");
        return -1;
    }
    if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain))
        die("GCM auth fail at R");

    printf("R(R%d) got plaintext: %.*s\n", cur, (int)pkt.p.ct_len, plain);

    int blocked = apply_policy_contract((const char *)plain);

    if (blocked) {
        printf("\n======= 責任追跡フェーズ =======\n");
        // Rの処理
        // トラフィックを通報
        // 本来は保存したS_pubとsigを使う
        // S_pub,sig,pkt,plain,node[NODES-1].sess_key,pi_concat,state_get_prev(me,pkt.h.sid),sigma_s


        // 検証者Vの処理
        // 通報の正当性検証
        unsigned char k_S[PUB_LEN];
        memcpy(k_S, kC_pub, PUB_LEN); // Sの公開鍵
        // 1) sigma 検証 (R_pub は known)
        if (!ed25519_verify(R_pub, payload, payload_len, sigma, siglen)) {
            fprintf(stderr, "Report signature invalid\n");
            return -1;
        }

        // 2) 通報パケットをパース
        

        // 3) SID 再計算: 例 -> SID = SHA256( S_pub ) or whatever your scheme uses
        unsigned char sid_chk[SID_LEN];
        // --- 署名をバイナリにエクスポート ---
        // byte_t *sig_bytes = NULL;
        // uint32_t sig_size = 0;
        groupsig_signature_export(&sig_bytes, &sig_size, sig);
        printf("Exported signature length: %u bytes\n", sig_size);

        // size_t sid_len;
        // unsigned char *sid 
        sid = concat2(k_S, PUB_LEN, sig_bytes, sig_size, &sid_len);
        // print_hex("sid", sid, sid_len);
        hash_sid_from_pub(sid, pkt.h.sid);
        // print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
        // parse_frame_to_pkt(frame, frame_len, &pkt); // 既存関数
        // Packet pkt;
        if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) { /* error */ }
        if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) { /* mismatch */ }
        printf("SID check: match\n");


        // 4) groupsig 検証
        // groupsig_signature_t *gsig = groupsig_signature_import(GROUPSIG_KTY04_CODE, groupsig_bytes, groupsig_len);
        uint8_t val;
        message_t *kSb = message_from_bytes(k_S, PUB_LEN);
        groupsig_verify(&val, sig, kSb, grpkey);
        printf("TGsig verification: %s\n", val ? "valid" : "invalid");

        // 5) ペイロード復号
        // ここでは pkt.p.iv, pkt.p.ct, pkt.p.tag を利用する
        unsigned char plain_out[MAX_PTXT];
        if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain_out)) {
            /* decrypt fail */
        }
        if (memcmp(plain_out, plain, sizeof(plain)) != 0) { /* mismatch */ }
        printf("Decrypt result match: %.*s\n", (int)pkt.p.ct_len, plain_out);

        
        // === Open（署名者を特定） ===
        // crl, gml, mgrkeyの読み込み
        crl_t *crl = crl_init(GROUPSIG_KTY04_CODE); // 失効リスト
        groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);

        
        // gml読み込み
        std::ifstream fgml("gml.dat", std::ios::binary);
        std::vector<unsigned char> buf((std::istreambuf_iterator<char>(fgml)), {});
        gml_t *gml = gml_import(GROUPSIG_KTY04_CODE, buf.data(), buf.size());

        uint64_t id = UINT64_MAX;
        int rc = groupsig_open(&id, NULL, NULL, sig, grpkey, mgrkey, gml);
        if (rc == IOK) {
            printf("Open success: member ID = %lu\n", id);
        } else {
            printf("Open failed.\n");
        }

        // ******************各ルータに問い合わせてS特定

        // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
        trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
        rc = groupsig_reveal(trapdoor, crl, gml, id);
        if (rc == IOK && trapdoor != NULL) {
            printf("Reveal success: trapdoor valid, member ID = %lu added to CRL.\n", id);
        } else {
            printf("Reveal failed.\n");
        }
    
        // trapdoorとCRLをRに送信

        // Rの処理
        // === Trace（署名が公開済み(CRL登録済)メンバーによるものか確認） ===
        uint8_t traced = 0;
        rc = groupsig_trace(&traced, sig, grpkey, crl, NULL, NULL);
        if (rc == IOK) {
            printf("Trace result: %d (1 = traced, 0 = not traced)\n", (int)traced);
        } else {
            printf("Trace failed.\n");
        }
    } else {
        puts("Message allowed by policy.");
    }
    
    // 後処理
    for (int i=0;i<NODES;i++) {
        node_free(&nodes[i]);
    }
    return 0;
}