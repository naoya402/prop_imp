#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctime>
#include <iostream>
#include <fstream>
#include <vector>


#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"


#define PORT 9000
#define SERVER_ADDR "127.0.0.1"

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


// int main() {
//     // === 初期化 ===
//     groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    
//     // --- グループ公開鍵を PEM から読み込み ---
//     groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
//     // groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
//     // gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);

//     // // グループをセットアップ
//     // groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

//     char *grpkey_str = groupsig_grp_key_to_string(grpkey); // 確認用
//     printf("Group Public Key:\n%s\n", grpkey_str);
//     free(grpkey_str);
//     // int grpkey_size = groupsig_grp_key_get_size(grpkey);
//     // printf("Group Public Key Size: %d bytes\n", grpkey_size);
    
//     // --- メンバー鍵作成 ---
//     printf("11111111\n");
//     groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
//     printf("22222222\n");
//     // === Join Step 1: メンバーからマネージャへ送るメッセージを作る ===
//     message_t *m1 = message_init();
//     groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
//     // message_free(m1);
//     printf("33333333\n");

//     // --- ソケットで送信 ---
//     int sock = socket(AF_INET, SOCK_STREAM, 0);
//     sockaddr_in serv_addr{};
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_port = htons(9300);
//     inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);

//     if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
//         perror("connect");
//         return 1;
//     }

//     uint32_t len = htonl(m1->length);
//     send(sock, &len, sizeof(len), 0);
//     send(sock, m1->bytes, m1->length, 0);
//     printf("[Sender] Sent join request (%ld bytes)\n", m1->length);

//     // --- 応答 m2 を受信 ---
//     uint32_t resp_len_n;
//     recv(sock, &resp_len_n, sizeof(resp_len_n), 0);
//     uint32_t resp_len = ntohl(resp_len_n);

//     unsigned char *b = new unsigned char[resp_len];
//     recv(sock, b, resp_len, MSG_WAITALL);
//     printf("[Sender] Received response (%d bytes)\n", resp_len);

//     close(sock);

//     // === Join Step 2: 最終メンバー鍵を完成させる ===
//     groupsig_key_t *final_memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, b, resp_len);
//     char *memkey_str = groupsig_mem_key_to_string(final_memkey);
//     printf("Final Membership Key:\n%s\n", memkey_str);
//     free(memkey_str);
//     // Revealされたらこのfinal_memkeyで署名しても識別される
//     // std::cout << "[Sender] Membership key imported successfully.\n";

//     // 最終の鍵を保存
//     byte_t *mem_bytes = NULL;
//     uint32_t mem_size = 0;
//     groupsig_mem_key_export(&mem_bytes, &mem_size, final_memkey);

//     std::ofstream fmem("memkey.pem", std::ios::binary);
//     fmem.write((char*)mem_bytes, mem_size);
//     fmem.close();
//     printf("Exported memkey.pem (%d bytes)\n", mem_size);

//     free(mem_bytes);

//     delete[] b;
//     message_free(m1);
//     groupsig_mem_key_free(final_memkey);
//     groupsig_mem_key_free(memkey);
//     groupsig_grp_key_free(grpkey);
//     groupsig_clear(GROUPSIG_KTY04_CODE);
//     return 0;
// }


// // 事前の鍵準備コード
// int main() {
//     groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

//     groupsig_key_t *grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
//     groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
//     gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);
//     crl_t *crl = crl_init(GROUPSIG_KTY04_CODE);

//     // グループをセットアップ
//     groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

//     // char *grpkey_str = groupsig_grp_key_to_string(grpkey); // 確認用
//     // printf("Group Public Key:\n%s\n", grpkey_str);
//     // free(grpkey_str);

//     // int grpkey_size = groupsig_grp_key_get_size(grpkey);
//     // printf("Group Public Key Size: %d bytes\n", grpkey_size);

//     // --- グループ鍵エクスポート ---
//     byte_t *grp_bytes = NULL;
//     uint32_t grp_size = 0;
//     groupsig_grp_key_export(&grp_bytes, &grp_size, grpkey);

//     // std::ofstream fgrp("grpkey.pem", std::ios::binary);
//     // fgrp.write((char*)grp_bytes, grp_size);
//     // fgrp.close();
//     // printf("Exported grpkey.pem (%d bytes)\n", grp_size);

//     // --- マネージャ鍵エクスポート ---
//     byte_t *mgr_bytes = NULL;
//     uint32_t mgr_size = 0;
//     groupsig_mgr_key_export(&mgr_bytes, &mgr_size, mgrkey);
//     // std::ofstream fmgr("mgrkey.pem", std::ios::binary);
//     // fmgr.write((char*)mgr_bytes, mgr_size);
//     // fmgr.close();
//     // printf("Exported mgrkey.pem (%d bytes)\n", mgr_size);

//     // ===========ここまでが事前の鍵準備コード===========
//     // --- Join ---
//     groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE); // メンバー鍵
//     message_t *m1 = NULL, *m2 = NULL;// 加入要求と応答メッセージ

//     // ステップ 0: メンバが参加要求
//     groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);

//     // ステップ 1: マネージャが処理して応答
//     groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

//     // メンバが最終鍵(sk_c)を完成させる（import）
//     groupsig_key_t *final_memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, m2->bytes, m2->length);
//     // char *memkey_str = groupsig_mem_key_to_string(final_memkey);
//     // printf("Final Membership Key:\n%s\n", memkey_str);
//     // free(memkey_str);

//     message_free(m1);
//     message_free(m2);

//     // --- Sign & Verify ---
//     message_t *msg = message_from_string((char *)"Hello");
//     groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);

//     groupsig_sign(sig, msg, final_memkey, grpkey, UINT_MAX);
//     byte_t *sig_bytes = NULL;
//     uint32_t sig_size = 0;
//     groupsig_signature_export(&sig_bytes, &sig_size, sig);

//     printf("Sig_bytes: %u\n", sig_size);
//     // char * str = groupsig_signature_to_string(sig);
//     // printf("Signature:\n%s\n", str);
//     // free(str);

//     uint8_t valid;
//     groupsig_verify(&valid, sig, msg, grpkey);
//     printf("Verification: %d\n", (int)valid);

//     // === Open（署名者を特定） ===
//     uint64_t idx = UINT64_MAX;
//     int rc = groupsig_open(&idx, NULL, NULL, sig, grpkey, mgrkey, gml);
//     if (rc == IOK) {
//         printf("Open success: member index = %llu\n", (unsigned long long)idx);
//     } else {
//         fprintf(stderr, "Open failed.\n");
//     }

//     // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
//     trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
//     rc = groupsig_reveal(trapdoor, crl, gml, idx);
//     if (rc == IOK && trapdoor != NULL) {
//         printf("Reveal success: trapdoor valid, member %llu added to CRL.\n", (unsigned long long)idx);
//     } else {
//         fprintf(stderr, "Reveal failed.\n");
//     }

//     // === Trace（署名が公開済み(CRL登録済)メンバーによるものか確認） ===
//     uint8_t traced = 0;
//     rc = groupsig_trace(&traced, sig, grpkey, crl, NULL, NULL);
//     if (rc == IOK) {
//         printf("Trace result: %d (1 = traced, 0 = not traced)\n", (int)traced);
//     } else {
//         fprintf(stderr, "Trace failed.\n");
//     }

//     // 後始末
//     groupsig_signature_free(sig);
//     groupsig_mem_key_free(final_memkey);
//     message_free(msg);
//     gml_free(gml);
//     groupsig_grp_key_free(grpkey);
//     groupsig_mgr_key_free(mgrkey);

//     groupsig_clear(GROUPSIG_KTY04_CODE);
//     return 0;
// }

#define CHECK_RC(rc, msg) \
    do { if ((rc) != IOK) { fprintf(stderr, "ERROR %s: rc=%d\n", (msg), (rc)); exit(1);} } while(0)

int main(void) {
    int rc;

    rc = groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    CHECK_RC(rc, "groupsig_init");

    groupsig_key_t *grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);//load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);//groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
    groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);//load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);//groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
    gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);
    crl_t *crl = crl_init(GROUPSIG_KTY04_CODE);
    if (!grpkey || !mgrkey || !gml || !crl) {
        fprintf(stderr, "NULL returned in key/gml/crl init\n");
        return 1;
    }
    // Setup (new group)
    rc = groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);
    CHECK_RC(rc, "groupsig_setup");

    // debug: sizes of keys
    int gsize = groupsig_grp_key_get_size(grpkey);
    int msize = groupsig_mgr_key_get_size(mgrkey);
    printf("grpkey size(meta): %d, mgrkey size(meta): %d\n", gsize, msize);

    // // Export grpkey for inspection
    // byte_t *grp_bytes = NULL; uint32_t grp_bytes_len = 0;
    // rc = groupsig_grp_key_export(&grp_bytes, &grp_bytes_len, grpkey);
    // CHECK_RC(rc, "groupsig_grp_key_export");
    // printf("grp_bytes_len=%u\n", grp_bytes_len);

    // --- Join flow ---
    groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
    if (!memkey) { fprintf(stderr,"memkey init failed\n"); return 1; }

    message_t *m1 = NULL, *m2 = NULL;
    rc = groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
    CHECK_RC(rc, "groupsig_join_mem");
    printf("m1 length=%lu\n", m1? m1->length : 0);

    rc = groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);
    CHECK_RC(rc, "groupsig_join_mgr");
    printf("m2 length=%lu\n", m2? m2->length : 0);

    groupsig_key_t *final_memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, m2->bytes, m2->length);
    if (!final_memkey) { fprintf(stderr,"final_memkey import failed\n"); return 1; }
    printf("final_memkey import ok\n");

    // // optional: export memkey for debugging
    // byte_t *mem_bytes = NULL; uint32_t mem_bytes_len = 0;
    // rc = groupsig_mem_key_export(&mem_bytes, &mem_bytes_len, final_memkey);
    // CHECK_RC(rc, "groupsig_mem_key_export");
    // printf("mem_bytes_len=%u\n", mem_bytes_len);

    // // free m1/m2
    message_free(m1); message_free(m2);
    
    // --- Sign & Verify ---
    message_t *msg = message_from_string((char *)"Hello");
    if (!msg) { fprintf(stderr,"message_from_string failed\n"); return 1; }
    
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
    if (!sig) { fprintf(stderr,"sig init failed\n"); return 1; }
    // printf("Join completed.\n");

    rc = groupsig_sign(sig, msg, final_memkey, grpkey, UINT_MAX);
    if (rc != IOK) {
        fprintf(stderr, "groupsig_sign failed rc=%d\n", rc);
        return 1;
    }

    byte_t *sig_bytes = NULL; uint32_t sig_size = 0;
    rc = groupsig_signature_export(&sig_bytes, &sig_size, sig);
    CHECK_RC(rc, "groupsig_signature_export");
    printf("sig_size=%u bytes\n", sig_size);

    uint8_t valid = 0;
    rc = groupsig_verify(&valid, sig, msg, grpkey);
    CHECK_RC(rc, "groupsig_verify(call)");
    printf("groupsig_verify returned OK; valid=%d\n", (int)valid);
    
    // If valid != 1, print diagnostics
    if (valid != 1) {
        fprintf(stderr, "VERIFY FAILED: valid=%d\n", valid);
        // print more info: sizes of grpkey, memkey, etc.
        // printf("grpkey get size: %d\n", groupsig_grp_key_get_size(grpkey));
        // printf("memkey get size: %d\n", groupsig_mem_key_get_size(final_memkey));
    }

    // // optional: string form
    // char *sig_str = groupsig_signature_to_string(sig);
    // if (sig_str) {
    //     printf("sig string len=%zu (print head 200 chars):\n%.200s\n", strlen(sig_str), sig_str);
    //     free(sig_str);
    // } else {
    //     printf("sig string is NULL\n");
    // }
    
    // === Open（署名者を特定） ===
    uint64_t idx = UINT64_MAX;
    rc = groupsig_open(&idx, NULL, NULL, sig, grpkey, mgrkey, gml);
    if (rc == IOK) {
        printf("Open success: member index = %llu\n", (unsigned long long)idx);
    } else {
        fprintf(stderr, "Open failed.\n");
    }

    // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
    trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
    rc = groupsig_reveal(trapdoor, crl, gml, idx);
    if (rc == IOK && trapdoor != NULL) {
        printf("Reveal success: trapdoor valid, member %llu added to CRL.\n", (unsigned long long)idx);
    } else {
        fprintf(stderr, "Reveal failed.\n");
    }

    // === Trace（署名が公開済み(CRL登録済)メンバーによるものか確認） ===
    uint8_t traced = 0;
    rc = groupsig_trace(&traced, sig, grpkey, crl, NULL, NULL);
    if (rc == IOK) {
        printf("Trace result: %d (1 = traced, 0 = not traced)\n", (int)traced);
    } else {
        fprintf(stderr, "Trace failed.\n");
    }

    // cleanup
    // free(grp_bytes);
    // free(mem_bytes);
    // free(sig_bytes);
    groupsig_signature_free(sig);
    groupsig_mem_key_free(final_memkey);
    message_free(msg);
    gml_free(gml);
    groupsig_grp_key_free(grpkey);
    groupsig_mgr_key_free(mgrkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);

    return 0;
}