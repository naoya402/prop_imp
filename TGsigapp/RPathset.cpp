#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include "func.h"

// 鍵をファイルから読み込み
groupsig_key_t *load_key_from_file(const char *path, uint8_t scheme,
                                   groupsig_key_t *(*import_func)(uint8_t, byte_t *, uint32_t)) {
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
    printf("=== R (Receiver) ===\n");

    // === Node群の初期化 ===
    Node nodes[NODES];
    for (int i = 0; i < NODES; i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }


    EVP_PKEY *sk = load_ed25519_seckey_pem("dh_sec.pem");
    // 公開鍵 raw を取得して SID を再計算
    unsigned char kC_pub[PUB_LEN];
    get_raw_pub(sk, kC_pub);
    unsigned char sid[SID_LEN];
    hash_sid_from_pub(kC_pub, sid);
    // print_hex("SID (Receiver)", sid, SID_LEN);
    // 受信側で τ4 を生成(復路の検証用 本来は state から取得)
    Node *n3 = &nodes[3];
    unsigned char t[SIG_LEN];
    size_t tau_len = SIG_LEN, g_len;
    unsigned char *g = concat2(sid, SID_LEN, n3->addr, 4, &g_len);
    sign_data(n3->sk, g, g_len, t, &tau_len);
    free(g);

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
    printf("[R] Waiting for sender connection on port %d...\n", PORT);

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    uint32_t len_n;
    recv(client_fd, &len_n, sizeof(len_n), 0);
    uint32_t pkt_len = ntohl(len_n);

    unsigned char frame[pkt_len];
    recv(client_fd, frame, pkt_len, MSG_WAITALL);
    // close(client_fd);
    printf("[R] Received %u bytes from sender\n", pkt_len);
    
    // printf("[R1] Received %zu bytes\n", total_read);
    // print_hex("Final frame", frame, pkt_len);

    // === パース/処理 ===
    if (router_handle_forward(frame, nodes) != 0) {
        fprintf(stderr, "Forward processing failed\n");
        return 1;
    }

    // レシーバRの処理
    // printf("\n=== Node R(R%d) ===\n", NODES - 1);
    Node *me = &nodes[NODES-1];
    Packet pkt;

    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "R: parse failed\n");
        return -1;
    }

    // print_hex("R received peer_pub", pkt.p.peer_pub, PUB_LEN);
    //　グループ署名の検証
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    size_t sig_len = pkt.p.sig_len;
    uint8_t valid;
    message_t *ppp = message_from_bytes(pkt.p.peer_pub, PUB_LEN);
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // char *cstr = groupsig_grp_key_to_string(grpkey);
    // printf("grpkey: %s\n", cstr);
    // free(cstr);
    groupsig_signature_t *gsig = groupsig_signature_import(GROUPSIG_KTY04_CODE, pkt.p.sig_bytes, pkt.p.sig_len);
    groupsig_verify(&valid, gsig, ppp, grpkey);
    printf("TGsig verification: %s\n", valid ? "valid" : "invalid");
    
    // Rもkを計算
    EVP_PKEY *S_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char shared[SEC_LEN];
    derive_shared(me->dh_sk, S_pub, shared);
    EVP_PKEY_free(S_pub);
    memcpy(me->sess_key, shared, KEY_LEN);
    me->has_sess = 1;
    print_hex("R derived k", me->sess_key, KEY_LEN);

    printf("\n===============================復路=================================");
    // レシーバRの処理
    printf("\n=== Node R(R%d) ===\n", NODES - 1);
    
    // ここでsidに紐づけてpi_concatを保存
    
    //復路の経路設定パケット作成
    memcpy(pkt.h.cid, me->state[0].precid, CID_LEN); // 往路の最後のサーキットIDを流用
    pkt.h.status = SETUP_RESP;
    pkt.h.idx--;
    pkt.h.idx--; // pi_concatサイズ計算のため加算しすぎたidxをもどす
    
    // ρ_sを生成
    size_t rho_len = SIG_LEN;
    unsigned char rho[SIG_LEN];
    size_t m_len;
    unsigned char *m= concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &m_len);
    // print_hex("m for rho", m, m_len);
    sign_data(me->sk, m, m_len, rho, &rho_len);
    free(m);
    memcpy(pkt.h.rho[(pkt.h.idx + 1) % 2], rho, SIG_LEN); // ρリストは2つ分だけ保持
    // print_hex("ρ", pkt.h.rho, SIG_LEN*2);

    // k_R を用意
    unsigned char kR_pub[PUB_LEN];
    get_raw_pub(me->dh_sk, kR_pub);
    memcpy(pkt.p.peer_pub, kR_pub, PUB_LEN);
    memcpy(pkt.p.rand_val, me->rand_val, sizeof(me->rand_val));

    // ==== SETUP_RESP をパケットに積む（DST_S と pi_concat を格納）====
    // 復路の送信フレームを作成
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    // print_hex("SID(R)", pkt.h.sid, SID_LEN);
    size_t wire_len = build_overlay_setup_resp(frame, sizeof(frame), &pkt);
    printf("R sending SETUP_RESP (%zu bytes)\n", wire_len);

    // 各ノードの処理
    // 復路は逆順に転送
    // int cur = nodes[ROUTERS].id;
    for (int i = ROUTERS; i >= 0; i--) {
        if (router_handle_reverse(frame, nodes) != 0) die("reverse fail");
        // Node *curN = &nodes[cur];
        // cur = state_get_prev(curN, pkt.h.sid);
    }

    // センダーSの処理
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "S: parse failed\n");
        // free(pkt);
        return -1;
    }
    // Sもkを計算
    me = &nodes[0];
    EVP_PKEY *R_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char kC_shared[SEC_LEN];
    derive_shared(me->dh_sk, R_pub, kC_shared);
    EVP_PKEY_free(R_pub);

    memcpy(me->sess_key, kC_shared, KEY_LEN);
    me->has_sess = 1;
    print_hex("S derived k", me->sess_key, KEY_LEN);

    // PKIから生成した鍵と同じか確認
    if (memcmp(me->sess_key, nodes[0].k[NODES-1], KEY_LEN) != 0) {
        die("k mismatch");
    }
    puts("== 経路設定完了・セッション確立 ==");

    printf("\n======= データ転送フェーズ =======\n");
    const char *msg = "hello world";
    size_t msg_len = strlen(msg);
    printf("S sending plaintext: %s\n", msg);

    // Sの処理: msgを暗号化して送信パケット作成
    unsigned char sid_use[SID_LEN];
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(nodes[0].dh_sk, kS_pub);
    hash_sid_from_pub(kS_pub, sid_use);
    memcpy(pkt.h.sid, sid_use, SID_LEN);

    pkt.h.status = DATA_TRANS;

    aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = msg_len;

    // ==== DATA_TRANS をパケットに積む ====
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);

    // 各ノードの処理: state.next で転送
    int cur = nodes[0].id;
    while (cur != NODES-1) {
        Node *me = &nodes[cur];
        if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
            fprintf(stderr, "parse failed\n");
            return -1;
        }
        printf("R%d -> ", me->id);
        int next_addr = state_get_next(me, pkt.h.sid);
        if (next_addr < 0) {
            die("no next hop in data forward");
        }
        cur = next_addr;
        //本来はcid更新
    }
    // Rの処理: 復号
    printf("R(R%d)\n", cur);
    unsigned char plain[MAX_PTXT];
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "R: parse failed\n");
        return -1;
    }
    if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain))
        die("GCM auth fail at R");

    printf("R(R%d) got plaintext: %.*s\n", cur, (int)pkt.p.ct_len, plain);

    int blocked = apply_policy_contract((const char *)plain);

    if (blocked) {
        printf("\n======= 責任追跡フェーズ =======\n");
        // Rの処理
        // トラフィックを通報
        // 本来は保存したS_pubとsigを使う
        // 以下の要素をすべて連結 sig_lenとpkt_len
        // S_pub,sig,pkt,plain,node[NODES-1].sess_key,pi_concat,state_get_prev(me,pkt.h.sid),sigma_s
        size_t r1_len, r2_len, r3_len, r4_len, r5_len, r6_len, r7_len, r8_len, r9_len;
        unsigned char *r1=NULL, *r2=NULL, *r3=NULL, *r4=NULL, *r5=NULL, *r6=NULL, *r7=NULL,*r8=NULL,*r9=NULL;

        // unsigned char k_S[PUB_LEN];
        // memcpy(k_S, kS_pub, PUB_LEN);
        unsigned char Sig[SIG_LEN];
        memcpy(Sig, gsig, sig_len);

        r1 = concat2(kS_pub, PUB_LEN, (unsigned char *)&sig_len, sizeof(sig_len), &r1_len);
        r2 = concat2(r1, r1_len, Sig, sig_len, &r2_len);
        r3 = concat2(r2, r2_len, (unsigned char *)wire_len, sizeof(wire_len), &r3_len);
        r4 = concat2(r3, r3_len, (unsigned char *)&pkt, sizeof(Packet), &r4_len);
        r5 = concat2(r4, r4_len, plain, (int)pkt.p.ct_len, &r5_len);
        r6 = concat2(r5, r5_len, nodes[NODES-1].sess_key, KEY_LEN, &r6_len);
        r7 = concat2(r6, r6_len, pkt.h.pi_concat, MAX_PI, &r7_len);
        int prev_state = state_get_prev(me, pkt.h.sid);
        r8 = concat2(r7, r7_len, (unsigned char *)&prev_state, sizeof(prev_state), &r8_len);
        print_hex("r6", r6, r6_len);

        unsigned char sigma_s[SIG_LEN];
        size_t sigma_s_len = SIG_LEN;

        sign_data(nodes[NODES-1].sk, r6, r6_len, sigma_s, &sigma_s_len);
        r9 = concat2(r8, r8_len, sigma_s, sigma_s_len, &r9_len);
        // print_hex("σ_s (signature by receiver)", sigma_s, sigma_s_len);

        // --- m2 を送信 ---
        uint32_t resp_len_n = htonl(r9_len);
        send(client_fd, &resp_len_n, sizeof(resp_len_n), 0);
        send(client_fd, r9, r9_len, 0);
        close(client_fd);
        printf("[R] Sent report (%zu bytes) to sender\n", r9_len);
        free(r1); free(r2); free(r3); free(r4); free(r5); free(r6); free(r7); free(r8); free(r9);
        

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
            
        // 後処理
    groupsig_signature_free(gsig);
    // groupsig_mem_key_free(memkey);
    groupsig_grp_key_free(grpkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);

    // free(sig_bytes);
    // free(sid);
    return 0;
}