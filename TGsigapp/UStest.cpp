// ecc_undeniable.c
// Compile: gcc ecc_undeniable.c -o ecc_undeniable -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "func.h"

#define CURVE_NID NID_secp256k1  // 変更可 (secp256r1 = NID_X9_62_prime256v1)

static int hash_to_scalar(const unsigned char *msg, size_t msglen, const BIGNUM *order, BIGNUM *out, BN_CTX *ctx) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(msg, msglen, digest);
    // convert digest to BIGNUM and reduce mod order
    if (!BN_bin2bn(digest, SHA256_DIGEST_LENGTH, out)) return 0;
    if (!BN_mod(out, out, order, ctx)) return 0;
    // ensure non-zero
    if (BN_is_zero(out)) if (!BN_one(out)) return 0;
    return 1;
}

// --- US_sign ---
int US_sign(const char *message, EC_GROUP *group, BIGNUM *order, BIGNUM *x, EC_POINT *Y, BN_CTX *ctx, unsigned char **sig, size_t *sig_len){
    if (!message || !group || !order || !x || !ctx || !sig_len) return 0;

    int ret = 0;
    BIGNUM *m_scalar = NULL;
    EC_POINT *M = NULL;
    EC_POINT *Z = NULL;
    *sig = NULL;

    // ensure order is set
    if (!EC_GROUP_get_order(group, order, ctx)) {
        fprintf(stderr,"EC_GROUP_get_order error\n");
        return 0;
    }

    // 1) hash -> scalar
    m_scalar = BN_new();
    if (!hash_to_scalar((const unsigned char*)message, strlen(message), order, m_scalar, ctx)) {
        fprintf(stderr,"hash_to_scalar error\n"); return 0;
    }
    // 2) M = m_scalar * G
    M = EC_POINT_new(group);
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    if (!EC_POINT_mul(group, M, NULL, G, m_scalar, ctx)) { fprintf(stderr,"M mul error\n"); return 0; }
    
    // 3) Z = x * M
    Z = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Z, NULL, M, x, ctx)) { fprintf(stderr,"Z mul error\n"); return 0; }
    
    // 4) serialize to compressed form
    *sig_len = EC_POINT_point2oct(group, Z, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    *sig = (unsigned char*)malloc(*sig_len);
    if (EC_POINT_point2oct(group, Z, POINT_CONVERSION_COMPRESSED, *sig, *sig_len, ctx) != (int)*sig_len) {
        fprintf(stderr,"EC_POINT_point2oct error\n"); return 0;
    }

    // print for debug
    print_hex("Signature Z", *sig, *sig_len);

    ret = 1;
    if (m_scalar) BN_free(m_scalar);
    if (M) EC_POINT_free(M);
    if (Z) EC_POINT_free(Z);
    return ret;
}

int US_challenge(EC_GROUP *group, const EC_POINT *Z, const EC_POINT *Y, const BIGNUM *order, BN_CTX *ctx, BIGNUM *a, BIGNUM *b, EC_POINT *W) {
    if (!group || !Z || !Y || !order || !ctx || !a || !b || !W) return 0;

    int ret = 0;
    EC_POINT *aZ = NULL;
    EC_POINT *bY = NULL;

    // sample a,b in [0, order-1]
    if (!BN_rand_range(a, order)) { fprintf(stderr,"BN_rand_range a error\n"); return 0; }
    if (!BN_rand_range(b, order)) { fprintf(stderr,"BN_rand_range b error\n"); return 0; }

    aZ = EC_POINT_new(group);
    bY = EC_POINT_new(group);
    if (!aZ || !bY) return 0;

    if (!EC_POINT_mul(group, aZ, NULL, Z, a, ctx)) { fprintf(stderr,"a*Z mul error\n"); return 0; }
    if (!EC_POINT_mul(group, bY, NULL, Y, b, ctx)) { fprintf(stderr,"b*Y mul error\n"); return 0; }

    if (!EC_POINT_add(group, W, aZ, bY, ctx)) { fprintf(stderr,"W add error\n"); return 0; }

    ret = 1;
    if (aZ) EC_POINT_free(aZ);
    if (bY) EC_POINT_free(bY);
    return ret;
}

int US_response(EC_GROUP *group, const EC_POINT *W, const BIGNUM *x, const BIGNUM *order, BN_CTX *ctx, EC_POINT *R) {
    if (!group || !W || !x || !order || !ctx || !R) return 0;
    int ret = 0;
    BIGNUM *xinv = NULL;

    xinv = BN_mod_inverse(NULL, x, order, ctx);
    if (!xinv) { fprintf(stderr,"BN_mod_inverse error\n"); return 0; }

    if (!EC_POINT_mul(group, R, NULL, W, xinv, ctx)) { fprintf(stderr,"R mul error\n"); return 0; }

    ret = 1;
// cleanup:
    if (xinv) BN_free(xinv);
    return ret;
}

int US_verify(EC_GROUP *group, const EC_POINT *R, const EC_POINT *M, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    if (!group || !R || !M || !a || !b || !ctx) return -1;
    int ret = 0;
    EC_POINT *aM = NULL;
    EC_POINT *bG = NULL;
    EC_POINT *Rprime = NULL;
    int cmp;

    aM = EC_POINT_new(group);
    bG = EC_POINT_new(group);
    Rprime = EC_POINT_new(group);
    if (!aM || !bG || !Rprime) return -1;

    const EC_POINT *G = EC_GROUP_get0_generator(group);

    if (!EC_POINT_mul(group, aM, NULL, M, a, ctx)) { fprintf(stderr,"a*M error\n"); return -1; }
    if (!EC_POINT_mul(group, bG, NULL, G, b, ctx)) { fprintf(stderr,"b*G error\n"); return -1; }
    if (!EC_POINT_add(group, Rprime, aM, bG, ctx)) { fprintf(stderr,"R' add error\n"); return -1; }

    cmp = EC_POINT_cmp(group, R, Rprime, ctx);
    if (cmp == 0) {
        ret = 1;
    }

    if (aM) EC_POINT_free(aM);
    if (bG) EC_POINT_free(bG);
    if (Rprime) EC_POINT_free(Rprime);
    return ret;
}


int main(int argc, char **argv) {
    // if (argc < 2) {
    //     fprintf(stderr, "Usage: %s message-string\n", argv[0]);
    //     return 1;
    // }

    const char *message = "hello";//argv[1];
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { fprintf(stderr,"BN_CTX_new error\n"); return 1; }

    // Curve and group
    EC_GROUP *group = EC_GROUP_new_by_curve_name(CURVE_NID);
    if (!group) { fprintf(stderr,"EC_GROUP_new error\n"); return 1; }
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    // order n and generator G
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    const EC_POINT *G = EC_GROUP_get0_generator(group);

    // generate private key x and public key Y = x*G
    BIGNUM *x = BN_new();
    if (!BN_rand_range(x, order)) { fprintf(stderr,"BN_rand_range error\n"); return 1; }

    EC_POINT *Y = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Y, NULL, G, x, ctx)) { fprintf(stderr,"pubkey mul error\n"); return 1; }


    // -------- Signing (Alice) --------
    // signature Z (compressed)
    size_t buf_len; // sufficient size
    unsigned char *buf = NULL;

    if (!US_sign(message, group, order, x, Y, ctx, &buf, &buf_len)) {
        fprintf(stderr,"US_sign error\n"); return 1;
    }
    
    // -------- Verification interaction (Bob -> Alice -> Bob) --------
    // decompress signature Z
    EC_POINT *Z = EC_POINT_new(group);
    if (!EC_POINT_oct2point(group, Z, buf, buf_len, ctx)) {
        fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
        return 1;
    }   
    // Bob computes challenge
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_POINT *W = EC_POINT_new(group);
    if (!US_challenge(group, Z, Y, order, ctx, a, b, W)) {
        fprintf(stderr,"US_challenge error\n"); return 1;
    }
    // Alice computes response
    EC_POINT *R = EC_POINT_new(group);
    if (!US_response(group, W, x, order, ctx, R)) {
        fprintf(stderr,"US_response error\n"); return 1;
    }
    // Bob verifies
    // Map message -> scalar m' -> M = m'*G
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar((const unsigned char*)message, strlen(message), order, m_scalar, ctx)) {
        fprintf(stderr,"hash_to_scalar error\n"); return 1;
    }
    EC_POINT *M = EC_POINT_new(group);
    if (!EC_POINT_mul(group, M, NULL, G, m_scalar, ctx)) {
        fprintf(stderr,"M mul error\n"); return 1;
    }
    int ver = US_verify(group, R, M, a, b, ctx);
    if (ver == 1) {
        printf("Signature CONFIRMED by interactive protocol.\n");
    } else if (ver == 0) {
        printf("Signature NOT confirmed.\n");
    }

    free(buf);


    // // Map message -> scalar m' -> M = m'*G
    // BIGNUM *m_scalar = BN_new();
    // if (!hash_to_scalar((const unsigned char*)message, strlen(message), order, m_scalar, ctx)) {
    //     fprintf(stderr,"hash_to_scalar error\n"); return 1;
    // }
    // EC_POINT *M = EC_POINT_new(group);
    // if (!EC_POINT_mul(group, M, NULL, G, m_scalar, ctx)) { fprintf(stderr,"M mul error\n"); return 1; }

    // // Sign: Z = x * M
    // EC_POINT *Z = EC_POINT_new(group);
    // if (!EC_POINT_mul(group, Z, NULL, M, x, ctx)) { fprintf(stderr,"Z mul error\n"); return 1; }

    // // signature Z (compressed)
    // size_t buf_len = EC_POINT_point2oct(group, Z, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    // unsigned char buf[buf_len];
    // EC_POINT_point2oct(group, Z, POINT_CONVERSION_COMPRESSED, buf, buf_len, ctx);
    // print_hex("Signature Z", buf, buf_len);

    // -------- Verification interaction (Bob -> Alice -> Bob) --------
    // // Map message -> scalar m' -> M = m'*G
    // BIGNUM *m_scalar = BN_new();
    // if (!hash_to_scalar((const unsigned char*)message, strlen(message), order, m_scalar, ctx)) {
    //     fprintf(stderr,"hash_to_scalar error\n"); return 1;
    // }
    // EC_POINT *M = EC_POINT_new(group);
    // if (!EC_POINT_mul(group, M, NULL, G, m_scalar, ctx)) { fprintf(stderr,"M mul error\n"); return 1; }
    // // signature Z1 (decompress)
    // EC_POINT *Z1 = EC_POINT_new(group);
    // if (!EC_POINT_oct2point(group, Z1, buf, buf_len, ctx)) {
    //     fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
    // }

    // // Bob chooses random a,b
    // BIGNUM *a = BN_new(); BN_rand_range(a, order);
    // BIGNUM *b = BN_new(); BN_rand_range(b, order);

    // // compute W = a*Z + b*Y
    // EC_POINT *aZ = EC_POINT_new(group);
    // EC_POINT *bY = EC_POINT_new(group);
    // EC_POINT_mul(group, aZ, NULL, Z1, a, ctx);   // a*Z
    // EC_POINT_mul(group, bY, NULL, Y, b, ctx);   // b*Y

    // EC_POINT *W = EC_POINT_new(group);
    // EC_POINT_add(group, W, aZ, bY, ctx);

    // // Alice computes x^{-1} mod order
    // BIGNUM *xinv = BN_mod_inverse(NULL, x, order, ctx);
    // if (!xinv) { fprintf(stderr,"BN_mod_inverse error\n"); return 1; }

    // // Alice computes R = x^{-1} * W and returns to Bob
    // EC_POINT *R = EC_POINT_new(group);
    // EC_POINT_mul(group, R, NULL, W, xinv, ctx);

    // // Bob computes R' = a*M + b*G
    // EC_POINT *aM = EC_POINT_new(group);
    // EC_POINT *bG = EC_POINT_new(group);
    // EC_POINT_mul(group, aM, NULL, M, a, ctx);
    // EC_POINT_mul(group, bG, NULL, G, b, ctx);
    // EC_POINT *Rprime = EC_POINT_new(group);
    // EC_POINT_add(group, Rprime, aM, bG, ctx);

    // // Compare R and Rprime
    // if (0 == EC_POINT_cmp(group, R, Rprime, ctx)) {
    //     printf("Signature CONFIRMED by interactive protocol.\n");
    // } else {
    //     printf("Signature NOT confirmed.\n");
    // }

    // // cleanup
    // EC_POINT_free(M); 
    // // EC_POINT_free(Z); 
    // EC_POINT_free(Y);
    // EC_POINT_free(aZ); EC_POINT_free(bY); EC_POINT_free(W);
    // EC_POINT_free(R); EC_POINT_free(Rprime); EC_POINT_free(aM); EC_POINT_free(bG);
    // BN_free(x); BN_free(m_scalar); BN_free(order); BN_free(a); BN_free(b); BN_free(xinv);
    // EC_GROUP_free(group);
    // BN_CTX_free(ctx);

    return 0;
}
