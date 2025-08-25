#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define ROUTERS 4 //Rn (1,...,n)
#define NODES ROUTERS + 2 // Rn (1,...,n), C(R0), S(Rn+1)
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
        int prev_id;
        int next_id;
    } state[MAX_STATE];
} Node;

static void die(const char *msg) {
    fprintf(stderr, "[FATAL] %s\n", msg);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
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

static EVP_PKEY* gen_ed25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("EVP_PKEY_keygen_init");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) die("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey; 
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


// Ed25519は秘密鍵から公開鍵を抽出する
static EVP_PKEY* extract_public_only(const EVP_PKEY *priv) {
    // For Ed25519, public key can be exported and re-imported as pub-only
    unsigned char pub[32];
    size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(priv, pub, &publen) <= 0) die("EVP_PKEY_get_raw_public_key");
    EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, publen);
    if (!pubkey) die("EVP_PKEY_new_raw_public_key");
    return pubkey;
}

// 署名と検証のための関数
static void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char **sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die("EVP_MD_CTX_new");
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) <= 0) die("EVP_DigestSignInit");
    // Ed25519 はハッシュ関数を使用しないので、NULLを指定
    if (EVP_DigestSign(mdctx, NULL, siglen, data, datalen) <= 0) die("EVP_DigestSign(size)");
    *sig = (unsigned char*)OPENSSL_malloc(*siglen);
    if (!*sig) die("OPENSSL_malloc");
    if (EVP_DigestSign(mdctx, *sig, siglen, data, datalen) <= 0) die("EVP_DigestSign");
    EVP_MD_CTX_free(mdctx);
}

static int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die("EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk) <= 0) die("EVP_DigestVerifyInit");
    int ok = EVP_DigestVerify(mdctx, sig, siglen, data, datalen);
    EVP_MD_CTX_free(mdctx);
    return ok == 1; // 1 = success, 0 = bad sig, <0 error
}

// メモリ確保のためのヘルパー関数
static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { perror("malloc"); exit(EXIT_FAILURE); }
    return p;
}

// 連結バイト列 a||b を作成
static unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen) {
    *outlen = alen + blen;
    unsigned char *buf = (unsigned char*)xmalloc(*outlen);
    memcpy(buf, a, alen);
    memcpy(buf + alen, b, blen);
    return buf;
}


// ---- ノード初期化 ----
static void node_init(Node *n, int id, const char *name) {
    memset(n, 0, sizeof(*n));
    n->id = id;
    snprintf(n->name, sizeof(n->name), "%s", name);
    RAND_bytes(n->addr, sizeof(n->addr));
    RAND_bytes(n->rand_val, sizeof(n->rand_val));
    n->sk = gen_ed25519_keypair();
    n->pk = extract_public_only(n->sk);
    // n->dh_sk = NULL;//gen_x25519_keypair();
    n->has_sess = 0;
}

static void node_free(Node *n) {
    if (n->dh_sk) EVP_PKEY_free(n->dh_sk);
    if (n->sk) EVP_PKEY_free(n->sk);
    if (n->pk) EVP_PKEY_free(n->pk);
}

int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // ノードの初期化
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

    // 各ノードの τ と π を保存する配列の初期化
    unsigned char *tau[NODES];
    size_t tau_len[NODES];
    unsigned char *pi[NODES];
    size_t pi_len[NODES];
    for (int i = 0; i < NODES; i++) {
    tau[i] = NULL;  tau_len[i] = 0;
    pi[i]  = NULL;  pi_len[i]  = 0;
    }
    
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
    // 経路設定パケット作成
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
    print_hex("m = sid||R0", m, m_len);
    sign_data(nodes[0].sk, m, m_len, &tau[0], &tau_len[0]);
    print_hex("τ0", tau[0], tau_len[0]);
    //パケットにτを格納
    // memcpy(pkt.p.tau, tau[0], tau_len[0]);
    // pkt.p.tau_len = tau_len[0];

    // 状態保存（prev=0, next=1 or self）
    state_set(&nodes[0], pkt.h.sid, nodes[0].id, nodes[1].id);
    printf(state_get_next(&nodes[0], pkt.h.sid) == nodes[1].id ? "C state set OK\n" : "C state set NG\n");

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
        int next_id = (i < NODES-1) ? (nodes[i+1].id) : nodes[i].id;
        //前ホップを決定
        int prev_id = nodes[i-1].id;
        // 状態保存（prev=i-1, next=i+1 or self）
        state_set(me, pkt.h.sid, prev_id, next_id);

        // 前ノードの τ_{i-1} を検証
        m = concat2(pkt.h.sid, sizeof(pkt.h.sid)-1, nodes[i-1].addr, strlen((char*)nodes[i-1].addr), &m_len);
        // print_hex("m = sid||R", m, m_len);
        if (!verify_sig(nodes[prev_id].pk, m, m_len, tau[i-1], tau_len[i-1])) {
            printf("Verify τ%d failed\n", i-1);
            return EXIT_FAILURE;
        }
        printf("Verify τ%d success\n", i-1);
        free(m);
        // π_i = Sign(sk_i, τ_{i-1} || r_i)
        n = concat2(tau[i-1], tau_len[i-1], nodes[i].rand_val, sizeof(nodes[i].rand_val), &n_len);
        sign_data(nodes[i].sk, n, n_len, &pi[i], &pi_len[i]);
        printf("π%d", i);
        print_hex(" ", pi[i], pi_len[i]);
        free(n);

        if(me->id != nodes[NODES-1].id) {
            // τ_i = Sign(sk_i, sid||R_i)
            m2 = concat2(pkt.h.sid, sizeof(pkt.h.sid)-1, nodes[i].addr, strlen((char*)nodes[i].addr), &m2_len);
            sign_data(nodes[i].sk, m2, m2_len, &tau[i], &tau_len[i]);
            printf("τ%d", i);
            print_hex(" ", tau[i], tau_len[i]);
            free(m2);
        }
    }

    // サーバSの処理
    printf("\n=== Node S(R%d) ===\n", NODES - 1);
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

    // π[1] ... π[NODES-1] の連結リストpi_concatに対する署名DST_Sを生成
    size_t total_len = 0;
    for (int i = 1; i < NODES; i++) {
        total_len += pi_len[i];
    }
    unsigned char *pi_concat = malloc(total_len);
    if (!pi_concat) {
        fprintf(stderr, "malloc failed\n");
        return EXIT_FAILURE;
    }
    size_t offset = 0;
    for (int i = 1; i < NODES; i++) {
        memcpy(pi_concat + offset, pi[i], pi_len[i]);
        offset += pi_len[i];
    }

    // DST_S = Sign(skS, pi_concat)
    unsigned char *SigS = NULL;
    size_t SigS_len = 0;
    sign_data(nodes[NODES-1].sk, pi_concat, total_len, &SigS, &SigS_len);
    print_hex("DST_S (Double Signature Tag by S)", SigS, SigS_len);
    // free(pi_concat);

    printf("\n===============================復路=================================");
    pkt.h.status = SETUP_RESP;
    memcpy(pkt.p.peer_pub, kS_pub, PUB_LEN);

    // 復路は逆順に転送
    int cur = nodes[ROUTERS].id;
    while (cur != nodes[0].id) {
        printf("\n=== Node R%d ===\n", cur);
        // DST_Sを検証
        if (!verify_sig(nodes[NODES-1].pk, pi_concat, total_len, SigS, SigS_len)) {
            printf("Verify DST_S failed\n");
            return EXIT_FAILURE;
        }
        printf("Verify DST_S success\n");
        // π_i+1 を検証
        n = concat2(tau[cur], tau_len[cur], nodes[cur+1].rand_val, sizeof(nodes[cur+1].rand_val), &n_len);
        if (!verify_sig(nodes[cur+1].pk, n, n_len, pi[cur+1], pi_len[cur+1])) {
            printf("Verify π%d failed\n", cur+1);
            return EXIT_FAILURE;
        }
        printf("Verify π%d success\n", cur+1);
        free(n);
        Node *curN = &nodes[cur];
        int prev_id = state_get_prev(curN, pkt.h.sid);
        if (prev_id < 0) {
            die("no prev on S->...");
        }
        cur = prev_id;
    }
    free(pi_concat);

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


    printf("\n======= データ転送フェーズ =======\n");
    const char *msg = "hello world";
    size_t msg_len = strlen(msg);
    printf("C sending plaintext: %s\n", msg);

    // Cの処理: msgを暗号化して送信パケット作成
    memset(&pkt, 0, sizeof(pkt));
    unsigned char sid_use[SID_LEN];
    get_raw_pub(nodes[0].dh_sk, kC_pub);
    hash_sid_from_pub(kC_pub, sid_use);
    memcpy(pkt.h.sid, sid_use, SID_LEN);

    pkt.h.status = DATA_TRANS;
    memcpy(pkt.h.dest, dest_addr, 4);

    aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = msg_len;

    // 各ノードの処理: state.next で転送
    cur = nodes[0].id;
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
    for (int i=0;i<NODES;i++) {
        node_free(&nodes[i]);
        if (tau[i]) OPENSSL_free(tau[i]);
        if (pi[i]) OPENSSL_free(pi[i]);
    }
    if (SigS) OPENSSL_free(SigS);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
