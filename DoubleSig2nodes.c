#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ROUTERS 4
#define NODES ROUTERS+1 // R0, R1, R2, R3, R4

static void die_ossl(const char *msg) {
    fprintf(stderr, "[FATAL] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static EVP_PKEY* gen_ed25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) die_ossl("EVP_PKEY_CTX_new_id");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die_ossl("EVP_PKEY_keygen_init");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) die_ossl("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey; // contains both sk and pk
}

// Ed25519では、秘密鍵から公開鍵を抽出する必要がある
static EVP_PKEY* extract_public_only(const EVP_PKEY *priv) {
    // For Ed25519, public key can be exported and re-imported as pub-only
    unsigned char pub[32];
    size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(priv, pub, &publen) <= 0) die_ossl("EVP_PKEY_get_raw_public_key");
    EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, publen);
    if (!pubkey) die_ossl("EVP_PKEY_new_raw_public_key");
    return pubkey;
}

// 署名と検証のための関数群
static void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char **sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) <= 0) die_ossl("EVP_DigestSignInit");
    // Ed25519 ignores EVP_Digest*; it signs raw data.
    if (EVP_DigestSign(mdctx, NULL, siglen, data, datalen) <= 0) die_ossl("EVP_DigestSign(size)");
    *sig = (unsigned char*)OPENSSL_malloc(*siglen);
    if (!*sig) die_ossl("OPENSSL_malloc");
    if (EVP_DigestSign(mdctx, *sig, siglen, data, datalen) <= 0) die_ossl("EVP_DigestSign");
    EVP_MD_CTX_free(mdctx);
}

static int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk) <= 0) die_ossl("EVP_DigestVerifyInit");
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

// 便利関数: バイト列 a||b を作る
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

    // ---- 入力 ----
    const unsigned char SID[] = "Hash(k_C,sigma_C)";//k_CはDHの鍵、sigma_Cはグループ署名
    unsigned char R1_ADDR[] ="R1-addr";
    // printf("R1 address: %s\n", R1_ADDR);
    // unsigned char R1_rand1[] = rand() % 256; // R1のランダム値
    unsigned char R2_ADDR[] = "R2-addr";
    unsigned char R2_rand2[1];
    R2_rand2[0] = rand() % 256; // R2のランダム値
    // printf("R2 random value: %02x\n", R2_rand2[0]);

    // ---- 鍵生成（R1, R2）----
    EVP_PKEY *sk1 = gen_ed25519_keypair();  // R1 private
    EVP_PKEY *sk2 = gen_ed25519_keypair();  // R2 private
    EVP_PKEY *pk1 = extract_public_only(sk1);
    EVP_PKEY *pk2 = extract_public_only(sk2);

    // ---- τ1 = Sign(sk1, sid || R1) ----
    size_t m1_len;
    unsigned char *m1 = concat2(SID, sizeof(SID)-1, R1_ADDR, sizeof(R1_ADDR)-1, &m1_len);

    unsigned char *tau1 = NULL;
    size_t tau1_len = 0;
    sign_data(sk1, m1, m1_len, &tau1, &tau1_len);

    // 検証（R2 が R1 の署名を検証する想定）
    if (!verify_sig(pk1, m1, m1_len, tau1, tau1_len)) {
        fprintf(stderr, "Verify τ1 failed\n");
        return EXIT_FAILURE;
    }

    // ---- π2 = Sign(sk2, τ1 || r2) ----
    size_t n2_len;
    unsigned char *n2 = concat2(tau1, tau1_len, R2_rand2, sizeof(R2_rand2)-1, &n2_len);

    unsigned char *pi2 = NULL;
    size_t pi2_len = 0;
    sign_data(sk2, n2, n2_len, &pi2, &pi2_len);


    // ---- τ1 = Sign(sk1, sid || R1) ----
    size_t m2_len;
    unsigned char *m2 = concat2(SID, sizeof(SID)-1, R2_ADDR, sizeof(R2_ADDR)-1, &m2_len);

    unsigned char *tau2 = NULL;
    size_t tau2_len = 0;
    sign_data(sk2, m2, m2_len, &tau2, &tau2_len);


    // // 検証（第三者が R2 の二重署名を検証する想定）
    // if (!verify_sig(pk2, m2_part, m2_len, pi2, pi2_len)) {
    //     fprintf(stderr, "Verify π2 failed\n");
    //     return EXIT_FAILURE;
    // }

    // ---- 出力 ----
    print_hex("m1 = sid||R1", m1, m1_len);
    print_hex("τ1 (R1 sig on m1)", tau1, tau1_len);
    print_hex("n2 = τ1||r2", n2, n2_len);
    print_hex("π2 (R2 sig on m2)", pi2, pi2_len);
    print_hex("m2 = sid||R2", m2, m2_len);
    print_hex("τ2 (R2 sig on m2)", tau2, tau2_len);

    free(m1);
    free(n2);
    free(m2);
    OPENSSL_free(tau1);
    OPENSSL_free(pi2);
    OPENSSL_free(tau2);
    EVP_PKEY_free(sk1);
    EVP_PKEY_free(sk2);
    EVP_PKEY_free(pk1);
    EVP_PKEY_free(pk2);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}