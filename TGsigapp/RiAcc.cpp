// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"

#include "func.h"


int main(void) {
    // グループ署名初期化
    // groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    // groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // US context 初期化
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    // ノード初期化
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
    // inq: SID(32B) || Payload(41B) || next_addr(4B)|| ACSEG((ROUTERS-1)*32B) || challenge(33B) 
    // 末尾のACSEGだけ抽出
    // size_t acseg_concat_len = (ROUTERS) * ACSEG_LEN; //ルータの数が洩れてるからダメ
    size_t inq_offset = len - ACSEG_LEN - 33; // challenge(33B)分も引く
    unsigned char dt_acseg[ACSEG_LEN];
    memcpy(dt_acseg, inq + inq_offset, ACSEG_LEN);
    // print_hex("dt_acseg", dt_acseg, ACSEG_LEN);
    size_t W_len = 33;
    unsigned char W_bytes[W_len];
    memcpy(W_bytes, inq + inq_offset + ACSEG_LEN, W_len);
    // print_hex("W_bytes", W_bytes, W_len);
    // print_hex("inq without ACSEG", inq, inq_offset);

    // 1) アカウンタビリティセグメント検証
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
    if (memcmp(acseg, dt_acseg, ACSEG_LEN) == 0) {
        printf("R%d ACSEG match\n", me->id);
    } else {
        flags = 0;
        printf("R%d ACSEG mismatch\n", me->id);
    }

    // 2) sid 抽出
    size_t offset = 0;
    unsigned char sid[SID_LEN];
    memcpy(sid, inq + offset, SID_LEN); offset += SID_LEN;
    // print_hex("SID", sid, SID_LEN);

    // 3) stateから前ホップとτを取得
    int prev_addr = 3; //me->state[0].prev_addr; // 本来はsidからstateのアドレスを取得
    // // 受信側で τ_{prev_addr} を生成(検証用 本来は state から取得)
    Node *no = &nodes[prev_addr];
    unsigned char t[SIG_LEN];
    size_t tau_len = SIG_LEN, g_len;
    unsigned char *g = concat2(sid, SID_LEN, no->addr, 4, &g_len);
    sign_data(no->sk, g, g_len, t, &tau_len);
    free(g);
    // print_hex("τi generated at R1", t, tau_len);
    // unsigned char *tau = me->state[0].tau;

    // 4) レスポンスを生成
    EC_POINT *W = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, W, W_bytes, W_len, us->ctx)) {
        fprintf(stderr, "EC_POINT_oct2point(W) failed\n");
        return -1;
    }
    EC_POINT *R = EC_POINT_new(us->group);
    if (!US_response(us, W, me->us_x, R)) {
        fprintf(stderr,"US_response error\n"); return 1;
    }
    // Rをバイト列に変換
    size_t R_buf_len = EC_POINT_point2oct(us->group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    unsigned char R_bytes[R_buf_len];
    if (!EC_POINT_point2oct(us->group, R, POINT_CONVERSION_COMPRESSED, R_bytes, R_buf_len, us->ctx)) {
        fprintf(stderr, "EC_POINT_point2oct(R) failed\n");
        return -1;
    }
    // print_hex("R", R_bytes, R_buf_len);

    // 5) 検証者に返す
    // prev_addr(4B) || R(33B) || τ(SIG_LEN) || rand(4B) || flags(2B) 
    // size_t reinq_len = 4 + SIG_LEN + 2;
    unsigned char *reinq1; size_t reinq1_len;
    unsigned char *reinq2; size_t reinq2_len;
    unsigned char *reinq3; size_t reinq3_len;
    unsigned char *reinq; size_t reinq_len;
    
    reinq1 = concat2((unsigned char*)&prev_addr, 4, R_bytes, R_buf_len, &reinq1_len);
    reinq2 = concat2(reinq1, reinq1_len, t, SIG_LEN, &reinq2_len);
    reinq3 = concat2(reinq2, reinq2_len, me->rand_val, sizeof(me->rand_val), &reinq3_len);
    reinq = concat2(reinq3, reinq3_len, (unsigned char*)&flags, 2, &reinq_len);

    // print_hex("[Node] Sending reinq to Verifier: ", reinq, reinq_len);
    uint32_t reinq_len_n = htonl(reinq_len);
    send(client, &reinq_len_n, sizeof(reinq_len_n), 0);
    send(client, reinq, reinq_len, 0);
}
