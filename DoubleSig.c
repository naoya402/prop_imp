#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ROUTERS 4 //Rn (1,...,n)
#define NODES ROUTERS + 2 // Rn (1,...,n), C(R0), S(Rn+1)

static void die(const char *msg) {
    fprintf(stderr, "[FATAL] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static EVP_PKEY* gen_ed25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("EVP_PKEY_keygen_init");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) die("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey; // contains both sk and pk
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

int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    srand((unsigned int)time(NULL));

    const unsigned char SID[] = "Hash(k_C,sigma_C)";
    // unsigned char ADDR[NODES][32] = {"R0", "R1", "R2", "R3", "R4", "R5"};

    // 鍵ペア,アドレス,乱数作成
    EVP_PKEY *sk[NODES], *pk[NODES];
    unsigned char rand_val[NODES];
    unsigned char ADDR[NODES][32];
    for (int i = 0; i < NODES; i++) {
        sk[i] = gen_ed25519_keypair();
        pk[i] = extract_public_only(sk[i]);
        snprintf((char*)ADDR[i], sizeof(ADDR[i]), "R%d", i);
        rand_val[i] = rand() % 256;
    }

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

    //往路
    printf("\n===============================往路=================================");
    //クライアントCの処理
    printf("\n=== Node C(R0) ===\n");
    // τ_0 = Sign(sk_0, sid||R_0)
    m = concat2(SID, sizeof(SID)-1, ADDR[0], strlen((char*)ADDR[0]), &m_len);
    // print_hex("m = sid||R", m, m_len);
    sign_data(sk[0], m, m_len, &tau[0], &tau_len[0]);
    print_hex("τ0", tau[0], tau_len[0]);

    // ---- ルータ(R1から開始)のループ ----
    for (int i = 1; i < NODES - 1; i++) {
        printf("\n=== Node R%d ===\n", i);
        // 前ノードの τ_{i-1} を検証
        m = concat2(SID, sizeof(SID)-1, ADDR[i-1], strlen((char*)ADDR[i-1]), &m_len);
        // print_hex("m = sid||R", m, m_len);
        if (!verify_sig(pk[i-1], m, m_len, tau[i-1], tau_len[i-1])) {
            printf("Verify τ%d failed\n", i-1);
            return EXIT_FAILURE;
        }
        printf("Verify τ%d success\n", i-1);
        free(m);
        // π_i = Sign(sk_i, τ_{i-1} || r_i)
        n = concat2(tau[i-1], tau_len[i-1], &rand_val[i], sizeof(rand_val[i]), &n_len);
        sign_data(sk[i], n, n_len, &pi[i], &pi_len[i]);
        printf("π%d", i);
        print_hex(" ", pi[i], pi_len[i]);
        free(n);

        // τ_i = Sign(sk_i, sid||R_i)
        m2 = concat2(SID, sizeof(SID)-1, ADDR[i], strlen((char*)ADDR[i]), &m2_len);
        sign_data(sk[i], m2, m2_len, &tau[i], &tau_len[i]);
        printf("τ%d", i);
        print_hex(" ", tau[i], tau_len[i]);
        free(m2);
    }

    //サーバSの処理
    printf("\n=== Node S(R%d) ===\n", NODES - 1);
    // 前ノードの τ_{ROUTERS} を検証
    m = concat2(SID, sizeof(SID)-1, ADDR[ROUTERS], strlen((char*)ADDR[ROUTERS]), &m_len);
    // print_hex("m = sid||R", m, m_len);
    if (!verify_sig(pk[ROUTERS], m, m_len, tau[ROUTERS], tau_len[ROUTERS])) {
        printf("Verify τ%d failed\n", ROUTERS);
        return EXIT_FAILURE;
    }
    printf("Verify τ%d success\n", ROUTERS);
    free(m);
    // π_s = Sign(sk_s, τ_{ROUTERS} || r_s)
    n = concat2(tau[ROUTERS], tau_len[ROUTERS], &rand_val[NODES - 1], sizeof(rand_val[NODES - 1]), &n_len);
    sign_data(sk[NODES - 1], n, n_len, &pi[NODES - 1], &pi_len[NODES - 1]);
    printf("π%d", NODES - 1);
    print_hex(" ", pi[NODES - 1], pi_len[NODES - 1]);
    free(n);

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
    sign_data(sk[NODES-1], pi_concat, total_len, &SigS, &SigS_len);
    print_hex("DST_S (Double Signature Tag by S)", SigS, SigS_len);
    // free(pi_concat);

    //復路
    printf("\n===============================復路=================================");
    for (int i =  ROUTERS; i > -1; i--) {
        printf("\n=== Node R%d ===\n", i);
        // DST_Sを検証
        if (!verify_sig(pk[NODES-1], pi_concat, total_len, SigS, SigS_len)) {
            printf("Verify DST_S failed\n");
            return EXIT_FAILURE;
        }
        printf("Verify DST_S success\n");
        // π_i+1 を検証
        n = concat2(tau[i], tau_len[i], &rand_val[i+1], sizeof(rand_val[i+1]), &n_len);
        if (!verify_sig(pk[i+1], n, n_len, pi[i+1], pi_len[i+1])) {
            printf("Verify π%d failed\n", i+1);
            return EXIT_FAILURE;
        }
        printf("Verify π%d success\n", i+1);
        free(n);
    }
    free(pi_concat);

    // ---- 後処理 ----
    for (int i = 0; i < NODES; i++) {
        EVP_PKEY_free(sk[i]);
        EVP_PKEY_free(pk[i]);
        if (tau[i]) OPENSSL_free(tau[i]);
        if (pi[i]) OPENSSL_free(pi[i]);
    }
    if (SigS) OPENSSL_free(SigS);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}