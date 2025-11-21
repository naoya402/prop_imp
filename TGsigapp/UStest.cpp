// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <openssl/bn.h>
// #include <openssl/ec.h>
// #include <openssl/evp.h>
// #include <openssl/sha.h>
// #include <openssl/rand.h>

#include "func.h"

int main(void) {
    unsigned char* message = (unsigned char *)"hello";//argv[1];
    // BN_CTX *ctx = BN_CTX_new();
    // if (!ctx) { fprintf(stderr,"BN_CTX_new error\n"); return 1; }

    // // Curve and group
    // EC_GROUP *group = EC_GROUP_new_by_curve_name(CURVE_NID);
    // if (!group) { fprintf(stderr,"EC_GROUP_new error\n"); return 1; }
    // EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    // // order n and generator G
    // BIGNUM *order = BN_new();
    // EC_GROUP_get_order(group, order, ctx);
    // const EC_POINT *G = EC_GROUP_get0_generator(group);

    // Initialize US context
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }


    // 各ノードで初期化する必要あり
    // generate private key x and public key Y = x*G
    BIGNUM *x = BN_new();
    if (!BN_rand_range(x, us->order)) { fprintf(stderr,"BN_rand_range error\n"); return 1; }

    EC_POINT *Y = EC_POINT_new(us->group);
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    if (!EC_POINT_mul(us->group, Y, NULL, G, x, us->ctx)) { fprintf(stderr,"pubkey mul error\n"); return 1; }


    // -------- Signing (Alice) --------
    // signature Z (compressed)
    size_t buf_len; // sufficient size
    unsigned char *buf = NULL;

    if (!US_sign(us,message, strlen((const char*)message), x, &buf, &buf_len)) {
        fprintf(stderr,"US_sign error\n"); return 1;
    }
    
    // -------- Verification interaction (Bob -> Alice -> Bob) --------
    // decompress signature Z
    // EC_POINT *Z = EC_POINT_new(group);
    // if (!EC_POINT_oct2point(group, Z, buf, buf_len, ctx)) {
    //     fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
    //     return 1;
    // }   
    // Bob computes challenge
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_POINT *W = EC_POINT_new(us->group);
    // EC_GROUP *group1 = EC_GROUP_new_by_curve_name(CURVE_NID);
    if (!US_challenge(us, buf, buf_len, Y, a, b, W)) {
        fprintf(stderr,"US_challenge error\n"); return 1;
    }
    // Alice computes response
    EC_POINT *R = EC_POINT_new(us->group);
    if (!US_response(us, W, x, R)) {
        fprintf(stderr,"US_response error\n"); return 1;
    }

    // // Bob verifies
    // int ver = US_verify(us, R, message, strlen((const char*)message), a, b);
    // if (ver == 1) {
    //     printf("Signature CONFIRMED.\n");
    // } else if (ver == 0) {
    //     printf("Signature NOT confirmed.\n");
    // }

    size_t v_len; // sufficient size
    unsigned char *v = NULL;

    int ver = US_NIZK_Confirm(us, message, strlen((const char*)message), x, Y, buf, buf_len, &v, &v_len);
    if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }

    // print_hex("NIZK Confirmation Message:", v, v_len);
    
    ver = US_NIZK_VerifyC(us, Y, Y, message, strlen((const char*)message), buf, buf_len, v, v_len);
    if (ver == 1) {
        printf("NIZK Signature CONFIRMED.\n");
    } else if (ver == 0) {
        printf("NIZK Signature NOT confirmed.\n");
    }

    BIGNUM *x2 = BN_new();
    if (!BN_rand_range(x2, us->order)) { fprintf(stderr,"BN_rand_range error\n"); return 1; }
    EC_POINT *Y2 = EC_POINT_new(us->group);
    if (!EC_POINT_mul(us->group, Y2, NULL, G, x2, us->ctx)) { fprintf(stderr,"pubkey mul error\n"); return 1; }
    size_t buf2_len;
    unsigned char *buf2 = NULL;
    unsigned char* message2 = (unsigned char *)"h";//argv[1];
    US_sign(us,message2, strlen((const char*)message2), x2, &buf2, &buf2_len);
    // generate private key x and public key Y = x*G

    size_t v2_len; // sufficient size
    unsigned char *v2 = NULL;
    ver = US_NIZK_Disavow(us, message, strlen((const char*)message), x, Y, buf, buf_len, &v2, &v2_len);
    if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
    
    // print_hex("NIZK Confirmation Message:", v2, v2_len);
    
    ver = US_NIZK_VerifyD(us, Y, Y, message, strlen((const char*)message), buf, buf_len, v2, v2_len);
    if (ver == 1) {
        printf("NIZK Signature DISAVOWED.\n");
    } else if (ver == 0) {
        printf("NIZK Signature NOT disavowed.\n"); //こっちが正しい
    }

    ver = US_NIZK_Disavow(us, message2, strlen((const char*)message2), x, Y, buf2, buf2_len, &v2, &v2_len);
    if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
    
    // print_hex("NIZK Confirmation Message:", v2, v2_len);
    
    ver = US_NIZK_VerifyD(us, Y, Y, message2, strlen((const char*)message2), buf2, buf2_len, v2, v2_len);
    if (ver == 1) {
        printf("NIZK Signature DISAVOWED.\n");//こっちが正しい
    } else if (ver == 0) {
        printf("NIZK Signature NOT disavowed.\n");
    }

    // ------------- EC Commitment -------------
    unsigned char *commit = NULL;
    size_t commit_len = 0;
    ver = EC_Commit(us, message, strlen((const char*)message), (unsigned char *)"randomness", strlen("randomness"), G, &commit, &commit_len);
    if (!ver) { fprintf(stderr,"EC_Commit error\n"); return 1; }
    // print_hex("EC Commitment:", commit, commit_len);

    ver = EC_Com_Verify(us, message, strlen((const char*)message), (unsigned char *)"randomness", strlen("randomness"), G, commit, commit_len);
    if (ver == 1) {
        printf("EC Commitment VERIFIED.\n");
    } else if (ver == 0) {
        printf("EC Commitment NOT verified.\n");
    }

    // ver  = US_NIZK_Sign(us, message, strlen((const char*)message), x, Y, buf, buf_len, &sigma, &sigma_len);
    // if (!ver) { fprintf(stderr,"US_NIZK_Sign error\n"); return 1; }

    // ver = US_NIZK_Verify(us, Y, message, strlen((const char*)message), buf, buf_len, sigma, sigma_len);
    // if (ver == 1) {
    //     printf("NIZK Signature CONFIRMED.\n");
    // } else if (ver == 0) {
    //     printf("NIZK Signature NOT confirmed.\n");
    // }

    free(buf);
    return 0;
}