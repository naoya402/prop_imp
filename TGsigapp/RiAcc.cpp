// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"

#include "func.h"

#define PORT 9200
#define SERVER_ADDR "127.0.0.1"


int main(void) {
    // signal(SIGPIPE, SIG_IGN);
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
    // uint32_t len_n;
    // recv(client, &len_n, sizeof(len_n), 0);
    // uint32_t len = ntohl(len_n);

    // unsigned char inq[len];
    // recv(client, inq, len, MSG_WAITALL);
    /* --- 応答 (暗号化) を受信 --- */
    uint32_t resp_len_n;
    if (recv(client, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
        perror("recv len");
        close(client);
        return 1;
    }
    uint32_t resp_len = ntohl(resp_len_n);
    unsigned char *enc_inq = (unsigned char*)malloc(resp_len);
    if (!enc_inq) { close(client); return 1; }

    if (recv(client, enc_inq, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
        perror("recv body");
        free(enc_inq);
        close(client);
        return 1;
    }
    printf("[Node] Received (encrypted) inq (%d bytes)\n", resp_len);
    // print_hex("Encrypted inq", enc_inq, resp_len);

    /* 復号 */
    unsigned char *dec = NULL;
    int dec_len = 0;
    if (tls_decrypt(enc_inq, resp_len, &dec, &dec_len) != 0) {
        fprintf(stderr, "tls_decrypt failed (response)\n");
        free(enc_inq);
        close(client);
        return 1;
    }
    /* dec_len は resp_len の復号後の長さ */
    printf("[Node] Decrypted inq (%d bytes plaintext)\n", dec_len);
    free(enc_inq);
    
    // print_hex("Decrypted inq", dec, dec_len);
     unsigned char inq[dec_len];
    memcpy(inq, dec, dec_len);
    // free(dec);

    // printf("[Node] Received inq (%u bytes)\n", dec_len);
    // print_hex("inq", inq, dec_len);

    // 問い合わせパケットのパース
    // inq: SID(32B) || Payload(11B) || dh_pk_concat || com_concat || pi_concat || pi 
    size_t inq_offset = 0;
    // 1) SID
    unsigned char sid[SID_LEN];
    memcpy(sid, inq + inq_offset, SID_LEN); inq_offset += SID_LEN;
    // print_hex("SID", sid, SID_LEN);

    // 2) 平文 ct_len (2B)
    uint16_t ct_len_n;
    memcpy(&ct_len_n, inq + inq_offset, 2); inq_offset += 2;

    uint16_t ct_len = ntohs(ct_len_n);
    // printf("ct_len = %u\n", ct_len);

    // 3) CT（暗号文）
    unsigned char ct[ct_len];
    memcpy(ct, inq + inq_offset, ct_len); inq_offset += ct_len;
    // print_hex("CT", ct, ct_len);

    // 4) dh_pk_concat: cur_id * PUB_LEN
    int cur_id = me->id;  // ルータ自身のIDを使う
    size_t dh_concat_len = cur_id * PUB_LEN;
    unsigned char dh_pk_concat[dh_concat_len];
    memcpy(dh_pk_concat, inq + inq_offset, dh_concat_len); inq_offset += dh_concat_len;
    // print_hex("dh_pk_concat", dh_pk_concat, dh_concat_len);

    // 5) com_concat: (cur_id - 1) * USIG_LEN
    size_t com_concat_len = cur_id * USIG_LEN;
    unsigned char com_concat[com_concat_len];
    if (com_concat_len > 0) {
        memcpy(com_concat, inq + inq_offset, com_concat_len);
        // print_hex("com_concat", com_concat, com_concat_len);
    }
    inq_offset += com_concat_len;

    // 6) pi_concat_trim: (cur_id - 2) * USIG_LEN
    size_t pi_trim_len =  (cur_id - 1) * USIG_LEN;
    unsigned char pi_concat_trim[pi_trim_len];
    if (pi_trim_len > 0) {
        memcpy(pi_concat_trim, inq + inq_offset, pi_trim_len);
        // print_hex("pi_concat_trim", pi_concat_trim, pi_trim_len);
    }
    inq_offset += pi_trim_len;

    // 7) 最後の PI（1つ）= USIG_LEN
    unsigned char pi[USIG_LEN];
    memcpy(pi, inq + inq_offset, USIG_LEN); inq_offset += USIG_LEN;
    // print_hex("pi", pi, USIG_LEN);

    // // 1) アカウンタビリティセグメント検証
    // // HMACでACSEG生成
    // unsigned char acseg[ACSEG_LEN];
    // unsigned int acseg_len;
    // // 本来はノードが持つが、今回は便宜上ここで取得
    // unsigned char sharec[SEC_LEN];
    // derive_shared(me->dh_sk, nodes[0].dh_pk, sharec);
    // memcpy(me->ki, sharec, KEY_LEN);
    // // print_hex("me->ki", me->ki, KEY_LEN);
    // int hmac_result = hmac_sha256(me->ki, KEY_LEN, inq, inq_offset, acseg, &acseg_len);
    // if (hmac_result != 0) {
    //     fprintf(stderr,"HMAC failed\n");
    //     return -1;
    // }
    // // printf("R%d ACSEG: ", me->id); print_hex("", acseg, acseg_len);

    // //結果を集約する変数
    // int flags = 0; // すべて一致なら1
    // // acseg_concat内の自身のacsegと比較
    // if (memcmp(acseg, dt_acseg, ACSEG_LEN) == 0) {
    //     printf("R%d ACSEG match\n", me->id);
    //     flags = 1;
    // } else {
    //     printf("R%d ACSEG mismatch\n", me->id);
    // }

    // // 2) sid 抽出
    // size_t offset = 0;
    // unsigned char sid[SID_LEN];
    // memcpy(sid, inq + offset, SID_LEN); offset += SID_LEN;
    // // print_hex("SID", sid, SID_LEN);

    // 1) stateから前ホップとτを取得
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
    // EC_POINT *W = EC_POINT_new(us->group);
    // if (!EC_POINT_oct2point(us->group, W, W_bytes, W_len, us->ctx)) {
    //     fprintf(stderr, "EC_POINT_oct2point(W) failed\n");
    //     return -1;
    // }
    // EC_POINT *R = EC_POINT_new(us->group);
    // if (!US_response(us, W, me->us_x, R)) {
    //     fprintf(stderr,"US_response error\n"); return 1;
    // }
    // // Rをバイト列に変換
    // size_t R_buf_len = EC_POINT_point2oct(us->group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    // unsigned char R_bytes[R_buf_len];
    // if (!EC_POINT_point2oct(us->group, R, POINT_CONVERSION_COMPRESSED, R_bytes, R_buf_len, us->ctx)) {
    //     fprintf(stderr, "EC_POINT_point2oct(R) failed\n");
    //     return -1;
    // }
    // // print_hex("R", R_bytes, R_buf_len);
    
    // 2) 検証するvを生成
    unsigned char *n = NULL, *nn = NULL;
    size_t n_len, nn_len;
    n = concat2(com_concat, cur_id * USIG_LEN, pi_concat_trim, (cur_id - 1) * USIG_LEN, &n_len);
    nn = concat2(dh_pk_concat, cur_id * PUB_LEN, n, n_len, &nn_len);
    // print_hex("nn", nn, nn_len);
    
    size_t v_len; // sufficient size
    unsigned char *v = (unsigned char *)malloc(32 *3 + 33 * 2);
    int ver = US_NIZK_Confirm(us, nn, nn_len, me->us_x, me->us_y, pi, USIG_LEN, &v, &v_len);// 本来2つ目は次ノードの公開鍵
    if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
    // print_hex("v2", v2, v2_len);

    // 仮にvと同じにする　本来はdisavowを格納
    size_t vp_len;//= v_len;
    unsigned char *vp;// = v;
    ver = US_NIZK_Disavow(us, nn, nn_len, me->us_x, me->us_y, pi, USIG_LEN, &vp, &vp_len);// 本来2つ目は次ノードの公開鍵
    if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }

    // 3) flagsを取得
    int flags = 0; // すべて一致なら1
    // ステート内の自身のhashと比較
    unsigned char ct_hash[SHA256_DIGEST_LENGTH];
    SHA256(ct, ct_len, ct_hash);
    if (memcmp(ct_hash,  ct_hash, SHA256_DIGEST_LENGTH) == 0) {
        printf("R%d hash match\n", me->id);
        flags = 1;
    } else {
        printf("R%d hash mismatch\n", me->id);
    }


    // 5) 検証者に返す
    // v(162B) || vp(162B) || τ(SIG_LEN) || rand(4B) || prev_addr(4B) || flags(2B) 
    // size_t reinq_len = 4 + SIG_LEN + 2;
    unsigned char *reinq1; size_t reinq1_len;
    unsigned char *reinq2; size_t reinq2_len;
    unsigned char *reinq3; size_t reinq3_len;
    unsigned char *reinq4; size_t reinq4_len;
    unsigned char *reinq; size_t reinq_len;
    
    // reinq1 = concat2((unsigned char*)&prev_addr, 4, R_bytes, R_buf_len, &reinq1_len);
    // reinq2 = concat2(reinq1, reinq1_len, t, SIG_LEN, &reinq2_len);
    // reinq3 = concat2(reinq2, reinq2_len, me->state[0].rand_val, sizeof(me->state[0].rand_val), &reinq3_len);
    // reinq = concat2(reinq3, reinq3_len, (unsigned char*)&flags, 2, &reinq_len);
    // print_hex("reinq", reinq, reinq_len);
    reinq1 = concat2(v, v_len, vp, vp_len, &reinq1_len);
    reinq2 = concat2(reinq1, reinq1_len, t, SIG_LEN, &reinq2_len);
    // print_hex("τ3", t, SIG_LEN);
    reinq3 = concat2(reinq2, reinq2_len, me->state[0].rand_val, sizeof(me->state[0].rand_val), &reinq3_len);
    // print_hex("rand_val", me->state[0].rand_val, sizeof(me->state[0].rand_val));
    reinq4 = concat2(reinq3, reinq3_len, (unsigned char*)&prev_addr, 4, &reinq4_len);
    reinq = concat2(reinq4, reinq4_len, (unsigned char*)&flags, 2, &reinq_len);
    // print_hex("reinq", reinq, reinq_len);

    // print_hex("[Node] Sending reinq to Verifier: ", reinq, reinq_len);
    // uint32_t reinq_len_n = htonl(reinq_len);
    // send(client, &reinq_len_n, sizeof(reinq_len_n), 0);
    // send(client, reinq, reinq_len, 0);
    /* --- 暗号化して送信 --- */
    unsigned char *enc = NULL;
    int enc_len = 0;
    if (tls_encrypt(reinq, reinq_len, &enc, &enc_len) != 0) {
        fprintf(stderr, "tls_encrypt failed\n");
        close(client);
        return 1;
    }
    // printf("[Node] Encrypted reinq (%d bytes ciphertext + tag)\n", enc_len);
    uint32_t enc_len_n = htonl((uint32_t)enc_len);
    send(client, &enc_len_n, sizeof(enc_len_n), 0);
    send(client, enc, enc_len, 0);
    printf("[Node] Sent (encrypted) reinq request (%d bytes ciphertext + tag)\n", enc_len);

    free(enc);
    close(client);
    close(serv_sock);
    return 0;
}
