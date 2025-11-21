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
#include "func.h"

#define PORT 9000

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

    fread(buf, 1, len, f);
    fclose(f);

    groupsig_key_t *key = import_func(scheme, buf, len);
    free(buf);
    return key;
}

int main() {
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));

    // --- 既存の鍵読み込みまたは初期化 ---
    // printf("Group Public Key loaded.\n");
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);
    gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);

    // --- ソケット待受 ---
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(9300);
    bind(serv_sock, (sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(serv_sock, 1);

    printf("[Verifier] Waiting for join request...\n");

    int client_sock = accept(serv_sock, nullptr, nullptr);

    // // --- m1 受信 ---
    // uint32_t len_n;
    // recv(client_sock, &len_n, sizeof(len_n), 0);
    // uint32_t len = ntohl(len_n);


    // unsigned char *b = new unsigned char[len];
    // recv(client_sock, b, len, MSG_WAITALL);
    // printf("[Verifier] Received m1 (%d bytes)\n", len);

    // message_t *m1 = message_from_bytes(b, len);

    // --- (暗号化) m1 受信 ---
    uint32_t len_n;
    if (recv(client_sock, &len_n, sizeof(len_n), 0) != sizeof(len_n)) {
        perror("recv len");
        close(client_sock);
        close(serv_sock);
        return 1;
    }
    uint32_t len = ntohl(len_n);

    unsigned char *enc_buf = (unsigned char*)malloc(len);
    if (!enc_buf) { close(client_sock); close(serv_sock); return 1; }

    if (recv(client_sock, enc_buf, len, MSG_WAITALL) != (ssize_t)len) {
        perror("recv body");
        free(enc_buf);
        close(client_sock); close(serv_sock);
        return 1;
    }
    printf("[Verifier] Received (encrypted) m1 (%d bytes)\n", len);

    unsigned char *dec = NULL;
    int dec_len = 0;
    if (tls_decrypt(enc_buf, len, &dec, &dec_len) != 0) {
        fprintf(stderr, "tls_decrypt failed (m1)\n");
        free(enc_buf);
        close(client_sock); close(serv_sock);
        return 1;
    }
    free(enc_buf);

    message_t *m1 = message_from_bytes(dec, dec_len);

    message_t *m2 = message_init();

    // === Join Step 2: マネージャ応答 ===
    groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

    // // --- m2 を送信 ---
    // uint32_t resp_len_n = htonl(m2->length);
    // send(client_sock, &resp_len_n, sizeof(resp_len_n), 0);
    // send(client_sock, m2->bytes, m2->length, 0);
    // printf("[Verifier] Sent m2 (%ld bytes)\n", m2->length);
    /* 暗号化して送信 */
    unsigned char *enc_m2 = NULL;
    int enc_m2_len = 0;
    if (tls_encrypt(m2->bytes, m2->length, &enc_m2, &enc_m2_len) != 0) {
        fprintf(stderr, "tls_encrypt failed (m2)\n");
        close(client_sock); close(serv_sock);
        return 1;
    }
    uint32_t send_len_n = htonl((uint32_t)enc_m2_len);
    send(client_sock, &send_len_n, sizeof(send_len_n), 0);
    send(client_sock, enc_m2, enc_m2_len, 0);
    printf("[Verifier] Sent (encrypted) m2 (%d bytes ciphertext+tag)\n", enc_m2_len);
    free(enc_m2);

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

    // delete[] b;
    message_free(m1);
    message_free(m2);
    gml_free(gml);
    groupsig_grp_key_free(grpkey);
    // groupsig_mgr_key_free(mgrkey); //なぜかセグフォ 本来は解放すべき
    groupsig_clear(GROUPSIG_KTY04_CODE);
    return 0;
}
