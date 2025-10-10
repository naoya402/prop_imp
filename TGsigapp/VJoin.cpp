#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctime>
#include <iostream>
#include <fstream>
#include <vector>

// extern "C" {
#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/crl.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"
// }

#define PORT 9000

int main() {
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

    // --- 既存の鍵読み込みまたは初期化 ---
     std::ifstream fgrp("grpkey.pem", std::ios::binary);
    std::vector<unsigned char> buf1((std::istreambuf_iterator<char>(fgrp)), {});
    groupsig_key_t *grpkey = groupsig_grp_key_import(GROUPSIG_KTY04_CODE, buf1.data(), buf1.size());
    std::ifstream fmgr("mgrkey.pem", std::ios::binary);
    std::vector<unsigned char> buf2((std::istreambuf_iterator<char>(fmgr)), {});
    groupsig_key_t *mgrkey = groupsig_mgr_key_import(GROUPSIG_KTY04_CODE, buf2.data(), buf2.size());
    gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);

    // --- ソケット待受 ---
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);
    bind(serv_sock, (sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(serv_sock, 1);

    std::cout << "[Verifier] Waiting for join request...\n";

    int client_sock = accept(serv_sock, nullptr, nullptr);

    // --- m1 受信 ---
    uint32_t len_n;
    recv(client_sock, &len_n, sizeof(len_n), 0);
    uint32_t len = ntohl(len_n);

    unsigned char *b = new unsigned char[len];
    recv(client_sock, b, len, MSG_WAITALL);
    std::cout << "[Verifier] Received m1 (" << len << " bytes)\n";

    message_t *m1 = message_from_bytes(b, len);
    message_t *m2 = message_init();

    // === Join Step 2: マネージャ応答 ===
    groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

    // --- m2 を送信 ---
    uint32_t resp_len_n = htonl(m2->length);
    send(client_sock, &resp_len_n, sizeof(resp_len_n), 0);
    send(client_sock, m2->bytes, m2->length, 0);
    std::cout << "[Verifier] Sent m2 (" << m2->length << " bytes)\n";

    close(client_sock);
    close(serv_sock);

    // --- GML をファイルに保存 ---
    byte_t *gml_bytes = NULL;
    uint32_t gml_size = 0;
    gml_export(&gml_bytes, &gml_size, gml);

    std::ofstream fgml("gml.dat", std::ios::binary);
    fgml.write((char*)gml_bytes, gml_size);
    fgml.close();
    free(gml_bytes);

    delete[] b;
    message_free(m1);
    message_free(m2);
    gml_free(gml);
    groupsig_grp_key_free(grpkey);
    groupsig_mgr_key_free(mgrkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);
    return 0;
}
