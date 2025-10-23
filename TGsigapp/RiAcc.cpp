// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"

#include "func.h"


int main(void) {
    // groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    // groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // 初期化
    Node nodes[NODES];
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    // 今回はR4が受け取った仮定。本来はアドレスで自身を決める
    Node *me = &nodes[ROUTERS];

    // --- 通報パケット受信 ---
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9010);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(serv_sock, 1);
    printf("[Node] Waiting for report from Receiver...\n");

    int client = accept(serv_sock, NULL, NULL);
    uint32_t len_n;
    recv(client, &len_n, sizeof(len_n), 0);
    uint32_t len = ntohl(len_n);

    unsigned char inq[len];
    recv(client, inq, len, MSG_WAITALL);
    // printf("[Node] Received inq (%u bytes)\n", len);
    // print_hex("inq", inq, len);

    // 問い合わせパケットのパース
    // inq: SID(32B) || Payload(41B) || next_addr(4B)|| ACSEG((ROUTERS-1)*32B)
    // 末尾のACSEGだけ抽出
    size_t acseg_concat_len = (ROUTERS) * ACSEG_LEN;
    size_t inq_offset = len - acseg_concat_len;
    unsigned char acseg_concat[acseg_concat_len];
    memcpy(acseg_concat, inq + inq_offset, acseg_concat_len);
    // print_hex("acseg_concat", acseg_concat, acseg_concat_len);
    // print_hex("inq without ACSEG", inq, inq_offset);

    // HMACでACSEG生成
    unsigned char acseg[ACSEG_LEN];
    unsigned int acseg_len;
    // 本来はノードが持つが、今回は便宜上ここで取得
    unsigned char sharec[SEC_LEN];
    derive_shared(me->dh_sk, nodes[0].dh_pk, sharec);
    memcpy(me->ki, sharec, KEY_LEN);
    // print_hex("me->ki", me->ki, KEY_LEN);
    int hmac_result = hmac_sha256(me->ki, KEY_LEN, inq, inq_offset, acseg, &acseg_len);
    if (hmac_result != 0) {
        fprintf(stderr,"HMAC failed\n");
        return -1;
    }
    // printf("R%d ACSEG: ", me->id); print_hex("", acseg, acseg_len);

    //結果を集約する変数
    int flags = 1; // すべて一致なら1
    // acseg_concat内の自身のacsegと比較
    if (memcmp(acseg, acseg_concat + (me->id - 1) * ACSEG_LEN, ACSEG_LEN) == 0) {
        printf("R%d ACSEG match\n", me->id);
    } else {
        flags = 0;
        printf("R%d ACSEG mismatch\n", me->id);
    }

    size_t offset = 0;
    // 1)  抽出
    unsigned char sid[SID_LEN];
    memcpy(sid, inq + offset, SID_LEN); offset += SID_LEN;
    // print_hex("SID", sid, SID_LEN);

    // stateから前ホップとτを取得
    int prev_addr = 0; //me->state[0].prev_addr; // 本来はsidからstateのアドレスを取得
    // // 受信側で τ0 を生成(検証用 本来は state から取得)
    Node *no = &nodes[prev_addr];
    unsigned char t[SIG_LEN];
    size_t tau_len = SIG_LEN, g_len;
    unsigned char *g = concat2(sid, SID_LEN, no->addr, 4, &g_len);
    sign_data(no->sk, g, g_len, t, &tau_len);
    free(g);
    // print_hex("τi generated at R1", t, tau_len);
    // unsigned char *tau = me->state[0].tau;

    // 検証者に返す
    // prev_addr(4B) || τ(SIG_LEN) || rand(4B) || flags(2B)
    // size_t reinq_len = 4 + SIG_LEN + 2;
    unsigned char *reinq1; size_t reinq1_len;
    unsigned char *reinq2; size_t reinq2_len;
    unsigned char *reinq3; size_t reinq3_len;
    
    reinq1 = concat2((unsigned char*)&prev_addr, 4, t, SIG_LEN, &reinq1_len);
    reinq2 = concat2(reinq1, reinq1_len, me->rand_val, sizeof(me->rand_val), &reinq2_len);
    reinq3 = concat2(reinq2, reinq2_len, (unsigned char*)&flags, 2, &reinq3_len);

    // print_hex("[Node] Sending reinq to Verifier: ", reinq3, reinq3_len);
    uint32_t reinq_len_n = htonl(reinq3_len);
    send(client, &reinq_len_n, sizeof(reinq_len_n), 0);
    send(client, reinq3, reinq3_len, 0);
}
