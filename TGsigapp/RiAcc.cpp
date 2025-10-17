// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"

#include "func.h"

// // 鍵をファイルから読み込み
// groupsig_key_t *load_key_from_file(const char *path, uint8_t scheme,
//                                    groupsig_key_t *(*import_func)(uint8_t, byte_t *, uint32_t)) {
//     FILE *f = fopen(path, "rb");
//     if (!f) {
//         perror("fopen");
//         return NULL;
//     }

//     fseek(f, 0, SEEK_END);
//     long len = ftell(f);
//     rewind(f);

//     byte_t *buf = (byte_t *)malloc(len);
//     if (!buf) {
//         fclose(f);
//         return NULL;
//     }

//     fread(buf, 1, len, f);
//     fclose(f);

//     groupsig_key_t *key = import_func(scheme, buf, len);
//     free(buf);
//     return key;
// }


int main(void) {
    // groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    // groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // 初期化
    Node nodes[NODES];
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    Packet pkt;

    // unsigned char k_S[PUB_LEN];
    // get_raw_pub(nodes[0].dh_sk, k_S);
    // // memcpy(k_S, kC_pub, PUB_LEN);
    // unsigned char Sig[SIG_LEN];
    // memcpy(Sig, sig, sig_size);

    // --- 通報パケット受信 ---
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9100);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(serv_sock, 1);
    printf("[Verifier] Waiting for report from Receiver...\n");

    int client = accept(serv_sock, NULL, NULL);
    uint32_t len_n;
    recv(client, &len_n, sizeof(len_n), 0);
    uint32_t len = ntohl(len_n);

    unsigned char r9[len];
    recv(client, r9, len, MSG_WAITALL);
    printf("[Verifier] Received r9 (%u bytes)\n", len);
    // print_hex("r9", r9, len);    

    // ************問い合わせパケットのパース
    // 1)  抽出
    unsigned char k_S[PUB_LEN];
    memcpy(k_S, r9 + offset, PUB_LEN); offset += PUB_LEN;
    // print_hex("k_S", k_S, PUB_LEN);

    // 2) グループ署名（Sig）抽出
    // char *strsig = groupsig_signature_to_string(sig);
    // printf("V: gsig: %s\n", strsig);
    // free(strsig);


    // 3) Packet構造体の復元
    size_t pkt_len;
    memcpy(&pkt_len, r9 + offset, 8);//sizeof(pkt_len));
    offset += 8;//sizeof(pkt_len);
    // printf("pkt_len: %lu\n", pkt_len);
    // Packet pkt;
    unsigned char frame[pkt_len];
    memcpy(frame, r9 + offset, pkt_len); offset += pkt_len;
    // print_hex("frame", frame, pkt_len);
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
                fprintf(stderr, "parse failed\n");
                return -1;
    }

    // print_hex("ACSEG: ", pkt.h.acseg_concat, ACSEG_LEN * ROUTERS);

    // *************************MAC検証
    // SID || Payload || next_addr(4B)
    size_t ac_plain_len = SID_LEN + pay_len + 4;
    unsigned char *ac_plain1; size_t ac_plain1_len;
    unsigned char *ac_plain2; size_t ac_plain2_len;

    uint32_t next_addr_n = htonl((uint32_t)next_addr);
    ac_plain1 = concat2(pkt.h.sid, SID_LEN, pay_buf, pay_len, &ac_plain1_len);
    ac_plain2 = concat2(ac_plain1, ac_plain1_len, (unsigned char*)&next_addr_n, 4, &ac_plain2_len);
    // print_hex("AC_PLAIN: ", ac_plain2, ac_plain2_len);

    // HMACでACSEG生成
    unsigned char acseg[ACSEG_LEN];
    unsigned int acseg_len;
    int hmac_result = hmac_sha256(me->ki, KEY_LEN, ac_plain2, ac_plain2_len, acseg, &acseg_len);
    if (hmac_result != 0) {
        fprintf(stderr,"HMAC failed at R%d\n", idx);
        return -1;
    }
    // printf("R%d ACSEG: ", idx); print_hex("", acseg, acseg_len);
    size_t offset = 0;


    // ***********************stateから前ホップとτを取得


    // ****************************検証者に返す
}
