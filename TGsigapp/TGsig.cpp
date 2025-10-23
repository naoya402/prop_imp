// #include <iostream>
// #include <limits.h>

// #include "gtest/gtest.h"

// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/crl.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"

// groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

// groupsig_key_t *grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
// groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
// gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);

// groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

// // 加入
// groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
// message_t *m1 = message_init(), *m2 = message_init();
// groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
// groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

// // 署名と検証
// message_t *msg = message_from_string("Hello");
// groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
// groupsig_sign(sig, msg, memkey, grpkey, UINT_MAX);
// uint8_t valid;
// groupsig_verify(&valid, sig, msg, grpkey);

// // 開示（追跡）
// uint64_t idx;
// groupsig_open(&idx, NULL, NULL, sig, grpkey, mgrkey, gml);

// #include <stdio.h>
// #include <limits.h>
// #include <time.h>

// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/crl.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"

// int main() {
//     groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

//     groupsig_key_t *grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
//     groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
//     gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);

//     groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

//     // 加入
//     groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
//     message_t *m1 = message_init(), *m2 = message_init();
//     groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
//     groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

//     // 署名と検証
//     message_t *msg = message_from_string((char *)"Hello");
//     groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
//     groupsig_sign(sig, msg, memkey, grpkey, UINT_MAX);
//     uint8_t valid;
//     groupsig_verify(&valid, sig, msg, grpkey);
//     printf("Verification result: %d\n", valid);

//     // 開示（追跡）
//     uint64_t idx;
//     groupsig_open(&idx, NULL, NULL, sig, grpkey, mgrkey, gml);
//     printf("Opened member index: %llu\n", (unsigned long long)idx);

//     groupsig_clear(GROUPSIG_KTY04_CODE);
//     return 0;
// }


#include <iostream>
#include <limits.h>
#include <ctime>

// extern "C" {
#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/crl.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"
// }

// 鍵をファイルから読み込み
groupsig_key_t *load_key_from_file(const char *path, uint8_t scheme, groupsig_key_t *(*import_func)(uint8_t, byte_t *, uint32_t)) {
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

    // fread(buf, 1, len, f);
    size_t read_bytes = fread(buf, 1, len, f);
    fclose(f);
    if (read_bytes != (size_t)len) {
        fprintf(stderr, "Warning: expected %ld bytes, but read %zu bytes from %s\n",
                len, read_bytes, path);
    }

    printf("File length before import: %ld\n", len);
    groupsig_key_t *key = import_func(scheme, buf, len);
    // int grpkey_size = groupsig_grp_key_get_size(key);
    // printf("Group Public Key Size: %d bytes\n", grpkey_size);
    free(buf);
    return key;
}


int main() {
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

    // --- Setup --- グループの公開鍵(pk_g)とマネージャ鍵(sk_g)の生成
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);//groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
    // printf("grpkey: %p\n", grpkey);
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);//groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
    gml_t *gml = gml_init(GROUPSIG_KTY04_CODE); // グループメンバーリスト
    crl_t *crl = crl_init(GROUPSIG_KTY04_CODE); // 失効リスト

    // groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);//新規作成のみ使用!!!!

    // --- Join ---
    groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE); // メンバー鍵
    message_t *m1 = NULL, *m2 = NULL;// 加入要求と応答メッセージ

    // ステップ 0: メンバが参加要求
    groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);

    // ステップ 1: マネージャが処理して応答
    groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

    // メンバが最終鍵(sk_c)を完成させる（import）
    groupsig_key_t *final_memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, m2->bytes, m2->length);
    // printf ("final_memkey: %p\n", final_memkey);

    message_free(m1);
    message_free(m2);

    // --- Sign & Verify ---
    message_t *msg = message_from_string((char *)"Hello");
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);

    groupsig_sign(sig, msg, final_memkey, grpkey, UINT_MAX);
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);

    printf("Sig_bytes: %u\n", sig_size);
    // for (size_t i = 0; i < sig_size; i++) {
    //     printf("%02x", sig_bytes[i]);
    // }
    // printf("\n");

    uint8_t valid;
    groupsig_verify(&valid, sig, msg, grpkey);
    std::cout << "Verification: " << (int)valid << std::endl;

    // === Open（署名者を特定） ===
    uint64_t idx = UINT64_MAX;
    int rc = groupsig_open(&idx, NULL, NULL, sig, grpkey, mgrkey, gml);
    if (rc == IOK) {
        std::cout << "Open success: member index = " << idx << std::endl;
    } else {
        std::cerr << "Open failed." << std::endl;
    }

    // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
    trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
    rc = groupsig_reveal(trapdoor, crl, gml, idx);
    if (rc == IOK && trapdoor != NULL) {
        std::cout << "Reveal success: trapdoor valid, member " << idx << " added to CRL." << std::endl;
    } else {
        std::cerr << "Reveal failed." << std::endl;
    }

    // === Trace（署名が公開済み(CRL登録済)メンバーによるものか確認） ===
    uint8_t traced = 0;
    rc = groupsig_trace(&traced, sig, grpkey, crl, NULL, NULL);
    if (rc == IOK) {
        std::cout << "Trace result: " << (int)traced
                  << " (1 = traced, 0 = not traced)" << std::endl;
    } else {
        std::cerr << "Trace failed." << std::endl;
    }

    // 後始末
    groupsig_signature_free(sig);
    groupsig_mem_key_free(final_memkey);
    message_free(msg);
    gml_free(gml);
    groupsig_grp_key_free(grpkey);
    groupsig_mgr_key_free(mgrkey);

    groupsig_clear(GROUPSIG_KTY04_CODE);
    return 0;
}
