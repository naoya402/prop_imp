
#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include "func.h"

#define PORT 9001

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
    printf("=== Router R1 (Receiver) ===\n");

    // === Node群の初期化 ===
    Node nodes[NODES];
    for (int i = 0; i < NODES; i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    // // DPDK初期化（あなたの環境に合わせて）
    // uint16_t portid = 0;
    // if (rte_eal_init(0, nullptr) < 0) {
    //     fprintf(stderr, "DPDK init failed\n");
    //     return -1;
    // }

    // === TCPでセンダーから受信 ===
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    bind(server_fd, (sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(server_fd, 1);
    printf("[R1] Waiting for sender connection on port %d...\n", PORT);

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    // uint32_t len_n;
    // recv(client_fd, &len_n, sizeof(len_n), 0);
    // uint32_t pkt_len = ntohl(len_n);

    // unsigned char frame[pkt_len];
    // recv(client_fd, frame, pkt_len, MSG_WAITALL);
    // close(client_fd);
    // printf("[R1] Received %u bytes from sender\n", pkt_len);
    /* --- 応答 (暗号化) を受信 --- */
    uint32_t resp_len_n;
    if (recv(client_fd, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
        perror("recv len");
        close(client_fd);
        return 1;
    }
    uint32_t resp_len = ntohl(resp_len_n);
    unsigned char *enc_resp = (unsigned char*)malloc(resp_len);
    if (!enc_resp) { close(client_fd); return 1; }

    if (recv(client_fd, enc_resp, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
        perror("recv body");
        free(enc_resp);
        close(client_fd);
        return 1;
    }
    printf("[Sender] Received (encrypted) response (%d bytes)\n", resp_len);

    /* 復号 */
    unsigned char *dec = NULL;
    int dec_len = 0;
    if (tls_decrypt(enc_resp, resp_len, &dec, &dec_len) != 0) {
        fprintf(stderr, "tls_decrypt failed (response)\n");
        free(enc_resp);
        close(client_fd);
        return 1;
    }
    /* dec_len は resp_len の復号後の長さ */
    printf("[Sender] Decrypted response (%d bytes plaintext)\n", dec_len);
    free(enc_resp);
    
    // printf("[R1] Received %zu bytes\n", total_read);
    // print_hex("Final frame", frame, pkt_len);

    // === パース/処理 ===
    unsigned char frame[dec_len];
    memcpy(frame, dec, dec_len);
    if (router_handle_forward(frame, nodes) != 0) {
        fprintf(stderr, "Forward processing failed\n");
        return 1;
    }

    

    // // === DPDKで次ノードへ送信 ===
    // struct rte_mbuf *mbuf = rte_pktmbuf_alloc(rte_pktmbuf_pool_create("pool", 8192, 32, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()));
    // if (!mbuf) {
    //     fprintf(stderr, "mbuf alloc failed\n");
    //     return 1;
    // }

    // unsigned char *buf = rte_pktmbuf_mtod(mbuf, unsigned char*);
    // size_t wire_len = build_overlay_setup_req(buf, RTE_MBUF_DEFAULT_BUF_SIZE, &pkt);
    // mbuf->data_len = wire_len;
    // mbuf->pkt_len = wire_len;

    // uint16_t nb_tx = rte_eth_tx_burst(portid, 0, &mbuf, 1);
    // if (nb_tx == 1) {
    //     printf("[R1] Sent to next router via DPDK (%zu bytes)\n", wire_len);
    // } else {
    //     printf("[R1] DPDK TX failed\n");
    //     rte_pktmbuf_free(mbuf);
    // }

    close(server_fd);
    return 0;
}
