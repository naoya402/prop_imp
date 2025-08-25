#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define NODES   6
#define SID_LEN     32         // SHA-256
#define PUB_LEN     32         // X25519 raw public
#define SEC_LEN     32         // X25519 shared secret (pre-KDF)
#define KEY_LEN     32         // use 256-bit app key = HKDF-out (ここでは簡略化し直接SECを使用)
#define IV_LEN      12
#define TAG_LEN     16
#define MAX_STATE   8
#define MAX_PTXT    128

typedef enum { SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;

// ヘッダ・ペイロード・パケット・ノード
typedef struct {
    unsigned char sid[SID_LEN];
    unsigned char dest[4];
    uint8_t status;
} Header;

typedef struct {
    // 経路設定用: 公開鍵を格納（REQでは k_C、RESPでは k_S）
    unsigned char peer_pub[PUB_LEN];

    // データ転送用
    unsigned char iv[IV_LEN];
    unsigned char ct[MAX_PTXT];
    size_t        ct_len;
    unsigned char tag[TAG_LEN];
} Payload;

typedef struct {
    Header  h;
    Payload p;
} Packet;

typedef struct {
    int id;
    char name[8];
    unsigned char addr[4];

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
        int prev_id;
        int next_id;
    } state[MAX_STATE];
} Node;

static void die(const char *msg) {
    fprintf(stderr, "[FATAL] %s\n", msg);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *lbl, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", lbl, len);
    for (size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}

static void hash_sid_from_pub(const unsigned char *pub, unsigned char sid[SID_LEN]) {
    SHA256(pub, PUB_LEN, sid);
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

static void get_raw_pub(const EVP_PKEY *pkey, unsigned char pub[PUB_LEN]) {
    size_t len = PUB_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0 || len != PUB_LEN) die("get_raw_public_key");
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

// ---- ステート操作 ----
static void state_set(Node *n, const unsigned char sid[SID_LEN], int prev_id, int next_id) {
    for (int i=0;i<MAX_STATE;i++) {
        if (!n->state[i].used) {
            n->state[i].used = 1;
            memcpy(n->state[i].sid, sid, SID_LEN);
            n->state[i].prev_id = prev_id;
            n->state[i].next_id = next_id;
            return;
        }
    }
    die("state full");
}

static int state_get_next(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].next_id;
    }
    return -1;
}

static int state_get_prev(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].prev_id;
    }
    return -1;
}

// ---- ノード初期化 ----
static void node_init(Node *n, int id, const char *name) {
    memset(n, 0, sizeof(*n));
    n->id = id;
    snprintf(n->name, sizeof(n->name), "%s", name);
    RAND_bytes(n->addr, sizeof(n->addr));
    n->sk = gen_x25519_keypair();
    n->pk = NULL; // 省略可（必要なら公開鍵だけのobjを作る）
    n->has_sess = 0;
}

static void node_free(Node *n) {
    if (n->sk) EVP_PKEY_free(n->sk);
    if (n->pk) EVP_PKEY_free(n->pk);
}

// ===============================================================
// ノードは SID を検証(= H(k_Cpub) と Payload の k_Cpub が一致)し、
// state に {sid, prev, next} を保存して次へフォワード
// サーバは k_S を生成し、共有鍵を作り、RESP を逆方向に返送
// データ転送は sess_key を用いてAES-GCMで暗号化
// 転送は state から next を参照
// ===============================================================
int main(void) {
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // ノードの初期化
    Node nodes[NODES];
    node_init(&nodes[0], 0, "C(R0)");
    for (int i=1;i<NODES-1;i++) {
        char n_name[8];
        snprintf(n_name, sizeof(n_name), "R%d", i);
        node_init(&nodes[i], i, n_name);
        // printf("%s\n", nodes[i].name);
    }
    char s_name[8];
    snprintf(s_name, sizeof(s_name), "S(R%d)", NODES-1);
    node_init(&nodes[NODES-1], NODES-1, s_name);

    // 最終目的地(dest)はS
    unsigned char dest_addr[4];
    memcpy(dest_addr, nodes[NODES-1].addr, 4);

    printf("======= 経路設定フェーズ =======\n");
    // ==往路==
    // クライアントCの処理
    // 経路設定パケット作成
    Packet pkt; memset(&pkt, 0, sizeof(pkt));

    // k_C 公開鍵取り出し & SID=H(k_C)
    unsigned char kC_pub[PUB_LEN];
    get_raw_pub(nodes[0].sk, kC_pub);
    hash_sid_from_pub(kC_pub, pkt.h.sid);
    pkt.h.status = SETUP_REQ;
    memcpy(pkt.h.dest, dest_addr, 4);
    memcpy(pkt.p.peer_pub, kC_pub, PUB_LEN); // P に k_C を格納

    // 状態保存（prev=0, next=1 or self）
    state_set(&nodes[0], pkt.h.sid, nodes[0].id, nodes[1].id);

    print_hex("SID(C)=H(kC)", pkt.h.sid, SID_LEN);

    // 各ノードの処理
    for (int hop = 1; hop < NODES; hop++) {
        Node *me = &nodes[hop];

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
        int next_id = (hop < NODES-1) ? (nodes[hop+1].id) : nodes[hop].id;
        //前ホップを決定
        int prev_id = nodes[hop-1].id;
        // 状態保存（prev=hop-1, next=hop+1 or self）
        state_set(me, pkt.h.sid, prev_id, next_id);
    }

    // サーバSの処理
    Node *me = &nodes[NODES-1];
    // k_S を用意して共有鍵 k を計算
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(me->sk, kS_pub);

    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char shared[SEC_LEN];
    derive_shared(me->sk, C_pub, shared);
    EVP_PKEY_free(C_pub);

    memcpy(me->sess_key, shared, KEY_LEN);
    me->has_sess = 1;
    print_hex("S derived k", me->sess_key, KEY_LEN);

    // ==復路 (k_S を返す)==
    pkt.h.status = SETUP_RESP;
    memcpy(pkt.p.peer_pub, kS_pub, PUB_LEN);

    // 復路は逆順に転送
    int cur = me->id;
    while (cur != 0) {
        Node *curN = &nodes[cur];
        int prev_id = state_get_prev(curN, pkt.h.sid);
        if (prev_id < 0) {
            die("no prev on S->...");
        }
        cur = prev_id;
    }

    // Cもkを計算
    EVP_PKEY *S_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char kC_shared[SEC_LEN];
    derive_shared(nodes[0].sk, S_pub, kC_shared);
    EVP_PKEY_free(S_pub);

    memcpy(nodes[0].sess_key, kC_shared, KEY_LEN);
    nodes[0].has_sess = 1;
    print_hex("C derived k", nodes[0].sess_key, KEY_LEN);

    if (memcmp(nodes[0].sess_key, nodes[NODES-1].sess_key, KEY_LEN) != 0) {
        die("k mismatch");
    }
    puts("== 経路設定完了・セッション確立 ==");


    printf("\n======= データ転送フェーズ =======\n");
    const char *msg = "hello, anonymous world!";
    size_t msg_len = strlen(msg);
    printf("C sending plaintext: %s\n", msg);

    // Cの処理: msgを暗号化して送信パケット作成
    memset(&pkt, 0, sizeof(pkt));
    unsigned char sid_use[SID_LEN];
    get_raw_pub(nodes[0].sk, kC_pub);
    hash_sid_from_pub(kC_pub, sid_use);
    memcpy(pkt.h.sid, sid_use, SID_LEN);

    pkt.h.status = DATA_TRANS;
    memcpy(pkt.h.dest, dest_addr, 4);

    aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = msg_len;

    // 各ノードの処理: state.next で転送
    cur = 0;
    while (cur != NODES-1) {
        Node *me = &nodes[cur];
        // printf("%s forwarding packet...\n", me->name);
        printf("%s -> ", me->name);
        int next_id = state_get_next(me, pkt.h.sid);
        if (next_id < 0) {
            die("no next hop in data forward");
        }
        cur = next_id;
    }
    puts("");
    // Sの処理: 復号
    unsigned char plain[MAX_PTXT];
    if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain))
        die("GCM auth fail at S");
    printf("%s got plaintext: %.*s\n", nodes[NODES-1].name, (int)pkt.p.ct_len, plain);

    // 後処理
    for (int i=0;i<NODES;i++) node_free(&nodes[i]);
    EVP_cleanup();
    return 0;
}
