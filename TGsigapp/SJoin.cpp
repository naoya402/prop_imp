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

int main() {
    // === 初期化 ===
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

    // --- グループ公開鍵を PEM から読み込み ---
    std::ifstream fgrp("grpkey.pem", std::ios::binary);
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(fgrp)), {});
    groupsig_key_t *grpkey = groupsig_grp_key_import(GROUPSIG_KTY04_CODE, buf.data(), buf.size());

    // --- メンバー鍵作成 ---
    groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE);

    // === Join Step 1: メンバーからマネージャへ送るメッセージを作る ===
    message_t *m1 = message_init();
    groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);

    // --- ソケットで送信 ---
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);

    if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        return 1;
    }

    uint32_t len = htonl(m1->length);
    send(sock, &len, sizeof(len), 0);
    send(sock, m1->bytes, m1->length, 0);
    std::cout << "[Sender] Sent join request (" << m1->length << " bytes)\n";

    // --- 応答 m2 を受信 ---
    uint32_t resp_len_n;
    recv(sock, &resp_len_n, sizeof(resp_len_n), 0);
    uint32_t resp_len = ntohl(resp_len_n);

    unsigned char *b = new unsigned char[resp_len];
    recv(sock, b, resp_len, MSG_WAITALL);
    std::cout << "[Sender] Received response (" << resp_len << " bytes)\n";

    close(sock);

    // === Join Step 2: 最終メンバー鍵を完成させる ===
    groupsig_key_t *final_memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, b, resp_len);
    printf ("final_memkey: %p\n", final_memkey);
    // Revealされたらこのfinal_memkeyで署名しても識別される
    // std::cout << "[Sender] Membership key imported successfully.\n";

    // 最終の鍵を保存
    byte_t *mem_bytes = NULL;
    uint32_t mem_size = 0;
    groupsig_mem_key_export(&mem_bytes, &mem_size, final_memkey);

    std::ofstream fmem("memkey.pem", std::ios::binary);
    fmem.write((char*)mem_bytes, mem_size);
    fmem.close();
    std::cout << "Exported memkey.pem (" << mem_size << " bytes)\n";

    free(mem_bytes);

    delete[] b;
    message_free(m1);
    groupsig_mem_key_free(final_memkey);
    groupsig_mem_key_free(memkey);
    groupsig_grp_key_free(grpkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);
    return 0;
}


// // 事前の鍵準備コード
// int main() {
//     groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

//     groupsig_key_t *grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
//     groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
//     gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);

//     // グループをセットアップ
//     groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

//     // --- グループ鍵エクスポート ---
//     byte_t *grp_bytes = NULL;
//     uint32_t grp_size = 0;
//     groupsig_grp_key_export(&grp_bytes, &grp_size, grpkey);

//     std::ofstream fgrp("grpkey.pem", std::ios::binary);
//     fgrp.write((char*)grp_bytes, grp_size);
//     fgrp.close();
//     std::cout << "Exported grpkey.pem (" << grp_size << " bytes)\n";

//     // --- マネージャ鍵エクスポート ---
//     byte_t *mgr_bytes = NULL;
//     uint32_t mgr_size = 0;
//     groupsig_mgr_key_export(&mgr_bytes, &mgr_size, mgrkey);

//     std::ofstream fmgr("mgrkey.pem", std::ios::binary);
//     fmgr.write((char*)mgr_bytes, mgr_size);
//     fmgr.close();
//     std::cout << "Exported mgrkey.pem (" << mgr_size << " bytes)\n";

//     // メモリ解放
//     free(grp_bytes);
//     free(mgr_bytes);

//     groupsig_grp_key_free(grpkey);
//     groupsig_mgr_key_free(mgrkey);
//     groupsig_clear(GROUPSIG_KTY04_CODE);

//     return 0;
// }

