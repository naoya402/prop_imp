#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include "func.h"

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
    // printf("======= 経路設定フェーズ =======");
    // printf("\n===============================往路=================================");
    // printf("=== R (Receiver) ===\n");

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
    // 受信側で τ4 を生成(復路の検証用&通報用 本来は state から取得)
    Node *nod = &nodes[4];
    unsigned char t[SIG_LEN];
    size_t t_len = SIG_LEN, g_len;
    unsigned char *g = concat2(sid, SID_LEN, nod->addr, 4, &g_len);
    sign_data(nod->sk, g, g_len, t, &t_len);
    free(g);

    // // DPDK初期化（あなたの環境に合わせて）
    // uint16_t portid = 0;
    // if (rte_eal_init(0, nullptr) < 0) {
    //     fprintf(stderr, "DPDK init failed\n");
    //     return -1;
    // }

    // // === TCPでセンダーから受信 ===
    // int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    // sockaddr_in serv_addr{};
    // serv_addr.sin_family = AF_INET;
    // serv_addr.sin_port = htons(PORT);
    // serv_addr.sin_addr.s_addr = INADDR_ANY;
    // bind(server_fd, (sockaddr *)&serv_addr, sizeof(serv_addr));
    // listen(server_fd, 1);
    // printf("[R] Waiting for sender connection on port %d...\n", PORT);

    // int client_fd = accept(server_fd, NULL, NULL);
    // if (client_fd < 0) {
    //     perror("accept");
    //     return 1;
    // }

    // uint32_t len_n;
    // recv(client_fd, &len_n, sizeof(len_n), 0);
    // uint32_t pkt_len = ntohl(len_n);

    // unsigned char frame[pkt_len];
    // recv(client_fd, frame, pkt_len, MSG_WAITALL);
    // // close(client_fd);
    // printf("[R] Received %u bytes from sender\n", pkt_len);
    
    // // printf("[R1] Received %zu bytes\n", total_read);
    // // print_hex("Final frame", frame, pkt_len);

    // // === パース/処理 ===
    // if (router_handle_forward(frame, nodes) != 0) {
    //     fprintf(stderr, "Forward processing failed\n");
    //     return 1;
    // }

    // τ0用のデータ
    unsigned char tau[SIG_LEN];
    size_t tau_len = SIG_LEN;
    size_t m_len;
    unsigned char *m = NULL;

    printf("======= 経路設定フェーズ =======");
    printf("\n===============================往路=================================");
    // センダーSの処理
    printf("\n=== Node S(R0) ===\n");
    Packet pkt; 
    // k_C 公開鍵取り出し & SID=H(k_C)
    // unsigned char kC_pub[PUB_LEN];
    int idx = 0;
    Node *me = &nodes[idx];
    get_raw_pub(me->dh_sk, kC_pub);
    // print_hex("kC_pub", kC_pub, PUB_LEN);
    //グループ署名生成
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // char *cstr = groupsig_grp_key_to_string(grpkey);
    // printf("grpkey: %s\n", cstr);
    groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);
    // message_t *gsm = message_from_string((char *)kC_pub);
    message_t *gsm = message_from_bytes(kC_pub, PUB_LEN);
    // print_hex("gsm", gsm->bytes, gsm->length);
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
    groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);
    // char *strsig = groupsig_signature_to_string(sig);
    // printf("R: gsig: %s\n", strsig);
    // free(strsig);

    // --- 署名をバイナリにエクスポート ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    printf("Exported signature length: %u bytes\n", sig_size);
    

    // unsigned char* にキャスト（byte_t は typedef unsigned char）
    unsigned char *uc_sig = (unsigned char *)malloc(sig_size);
    memcpy(uc_sig, sig_bytes, sig_size);
    // print_hex("Group signature σ", uc_sig, sig_size);

    size_t sid_len;
    unsigned char *sid_concat = concat2(kC_pub, PUB_LEN, sig_bytes, sig_size, &sid_len);
    // print_hex("sid", sid, sid_len);
    hash_sid_from_pub(sid_concat, pkt.h.sid);
    print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
    // サーキットIDを生成
    RAND_bytes(pkt.h.cid, CID_LEN);
    pkt.h.status = SETUP_REQ;

    // 各ノードの共有鍵 k_i を計算 & c_i を生成
    unsigned char sharenode[SEC_LEN];
    for (int i = 1; i < NODES; i++) {
        derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
        memcpy(me->k[i], sharenode, KEY_LEN);
        // print_hex("ki", me->k[i], KEY_LEN);

        // 前後ホップ (例: prev=i-1, next=i+1)
        unsigned char *prehop  = nodes[i-1].addr;
        unsigned char *nexthop = (i == NODES - 1) ? nodes[i].addr : nodes[i+1].addr;
        unsigned char *nnexthop = (i >= NODES - 2) ? nodes[i].addr : nodes[i+2].addr;
        // printf("nnexthop: %d.%d.%d.%d\n", nnexthop[0], nnexthop[1], nnexthop[2], nnexthop[3]);

        size_t p_len;
        unsigned char *p = concat2(prehop, 4, nexthop, 4, &p_len);
        size_t ap_len;
        unsigned char *ap = concat2(p, p_len, nnexthop, 4, &ap_len);
        
        unsigned char ci[SEG_LEN];
        unsigned char iv[IV_LEN], tag[TAG_LEN];//, ci[SEG_LEN];
        aead_encrypt(me->k[i], ap, ap_len, pkt.h.sid, iv, ci, tag);
        // // リングバッファもどき(容量=ROUTERS)に c_iやタグを循環的に挿入
        size_t offset = (size_t)((i-1) % (ROUTERS + 1)) * (SEG_LEN + TAG_LEN + IV_LEN);//ROUTERS + 1では経路長が漏洩するため適切な固定長(12など)にする
        // print_hex("c_i||tag_i||iv_i", t2, t2_len);

        // memcpy(pkt.h.seg_concat + offset, t2, t2_len);
        // printf("offset=%zu\n", offset);
        memcpy(pkt.h.seg_concat + offset, ci, SEG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN, tag, TAG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN + TAG_LEN, iv, IV_LEN);
        free(p);  free(ap);
        // free(t1); free(t2);
    }

    // print_hex("seg_concat", pkt.h.seg_concat, (ROUTERS + 1) * (SEG_LEN + TAG_LEN + IV_LEN));
    // τ_0 = Sign(sk_0, sid || addr_C)を生成
    // unsigned char *k = NULL;
    m = concat2(pkt.h.sid, SID_LEN, nodes[idx].addr, sizeof(nodes[idx].addr), &m_len);
    sign_data(nodes[idx].sk, m, m_len, tau, &tau_len);
    free(m);

    //パケットにτを格納
    memcpy(pkt.p.tau, tau, tau_len);
    // print_hex("τ0", tau, tau_len);
    memcpy(pkt.p.peer_pub, kC_pub, PUB_LEN); // P に k_C を格納
    pkt.p.sig_len = sig_size;
    memcpy(pkt.p.sig_bytes, sig_bytes, sig_size);
    // print_hex("sig_bytes", pkt.p.sig_bytes, pkt.p.sig_len);

    // 状態保存（prev=0, next=1 or self）
    unsigned char precid[CID_LEN];
    //前のサーキットがないので0クリア
    memset(precid, 0, CID_LEN);
    state_set(&nodes[idx], pkt.h.sid, precid, pkt.h.cid, -1, nodes[idx + 1].id, nodes[idx + 2].id, pkt.p.tau, SIG_LEN);

    // 次のノードの位置を設定
    pkt.h.idx = 1;

    // ==== メモリに L2/L3 + overlay(SETUP_REQ) を構築（送信用）====
    // 往路の送信フレームを作成
    unsigned char frame[MAX_PKT]; 
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    size_t wire_len = build_overlay_setup_req(frame, sizeof(frame), &pkt);
    // SID(36) + seg_list(40*5) + πリスト(0) + peer_pub(32) + τ(64) = 332B
    printf("S sending SETUP_REQ (%zu bytes)\n", wire_len);

    // 各ノードの処理
    for (int i = 1; i < NODES; i++) {
        if (router_handle_forward(frame, nodes) != 0) die("forward fail");
    }

    // レシーバRの処理=======ここから本来RPathsetup.cpp=========
    // printf("\n=== Node R(R%d) ===\n", NODES - 1);
    // Node *
    me = &nodes[NODES-1];
    // Packet pkt;

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
    // groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
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

    // πリスト保存
    save_pi_list(pkt.h.sid, pkt.h.pi_concat, MAX_PI);

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
    size_t mrho_len;
    unsigned char *mrho= concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &mrho_len);
    // print_hex("m for rho", mrho, mrho_len);
    sign_data(me->sk, mrho, mrho_len, rho, &rho_len);
    // print_hex("ρ", rho, SIG_LEN);
    free(mrho);
    memcpy(pkt.h.rho[(pkt.h.idx + 1) % 2], rho, SIG_LEN); // ρリストは2つ分だけ保持
    // print_hex("ρ", (unsigned char *)pkt.h.rho, SIG_LEN*2);

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
    // size_t 
    wire_len = build_overlay_setup_resp(frame, sizeof(frame), &pkt);
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

    // // PKIから生成した鍵と同じか確認
    // if (memcmp(me->sess_key, nodes[0].k[NODES-1], KEY_LEN) != 0) {
    //     die("k mismatch");
    // }
    puts("== 経路設定完了・セッション確立 ==");

    printf("\n======= データ転送フェーズ =======\n");
    const char *msg = "hello world";
    size_t msg_len = strlen(msg);
    printf("S sending plaintext: %s\n", msg);

    // Sの処理: msgを暗号化して送信パケット作成
    printf("S -> ");
    unsigned char sid_use[SID_LEN];
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(nodes[0].dh_sk, kS_pub);
    hash_sid_from_pub(kS_pub, sid_use);
    memcpy(pkt.h.sid, sid_use, SID_LEN);

    pkt.h.status = DATA_TRANS;
    
    aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = msg_len;
    
    pkt.h.idx = 1;//　本来必要ないが1にしておく
    // ==== DATA_TRANS をパケットに積む ====
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);
    // printf("Data Trans frame wire_len=%zu \n", wire_len);

    // 各ノードの処理: state.next で転送
    int cur = nodes[1].id;
    while (cur != NODES-1) {
        // Node *me = &nodes[cur];
        // if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        //     fprintf(stderr, "parse failed\n");
        //     return -1;
        // }
        if (router_handle_data_trans(frame, nodes) != 0) die("reverse fail");
        // printf("R%d -> ", me->id);
        cur++;// = next_addr;
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
        // 通報用ビルド
        wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);
        // Rの処理
        // トラフィックを通報
        // 本来は保存したS_pubとsigを使う
        // 以下の要素をすべて連結 sig_lenとpkt_len
        // S_pub,sig,pkt,plain,node[NODES-1].sess_key,pi_concat,state_get_prev(me,pkt.h.sid),τ,sigma_s
        size_t r1_len, r2_len, r3_len, r4_len, r5_len, r6_len, r7_len, r8_len, r9_len, r10_len, report_len;
        unsigned char *r1=NULL, *r2=NULL, *r3=NULL, *r4=NULL, *r5=NULL, *r6=NULL, *r7=NULL,*r8=NULL,*r9=NULL,*r10=NULL, *report=NULL;

        // unsigned char k_S[PUB_LEN];
        // memcpy(k_S, kS_pub, PUB_LEN);
        // unsigned char Sig[sig_len];
        // memcpy(Sig, gsig, sig_len);
        // char *strsig = groupsig_signature_to_string(gsig);
        // printf("R: gsig: %s\n", strsig);
        // free(strsig);
        // --- 署名をバイナリにエクスポート ---
        byte_t *sig_bytes = NULL;
        uint32_t sig_size = 0;
        groupsig_signature_export(&sig_bytes, &sig_size, gsig);

        size_t l2l3_len = write_l2l3_min(frame, sizeof(frame));
        size_t total_len = l2l3_len + wire_len;
        
        r1 = concat2(kS_pub, PUB_LEN, (unsigned char *)&sig_size, sizeof(sig_size), &r1_len);// 32 + 2034B
        // print_hex("r1", r1, r1_len);
        r2 = concat2(r1, r1_len, (unsigned char *)sig_bytes, sig_size, &r2_len);// +4B
        // print_hex("r2", r2, r2_len);
        // printf("wire_len: %lu\n", wire_len);
        r3 = concat2(r2, r2_len, (unsigned char *)&total_len, sizeof(total_len), &r3_len);// +8B
        // print_hex("r3", r3, r3_len);
        r4 = concat2(r3, r3_len, frame, total_len, &r4_len); // 34 + 205B
        // print_hex("r4", r4, r4_len);
        r5 = concat2(r4, r4_len, plain, (int)pkt.p.ct_len, &r5_len); // +11B
        r6 = concat2(r5, r5_len, nodes[NODES-1].sess_key, KEY_LEN, &r6_len); // +32B
        r7 = concat2(r6, r6_len, pkt.h.pi_concat, MAX_PI, &r7_len);// 320B
        int prev_state = ROUTERS;//state_get_prev(me, pkt.h.sid); //本来アドレスを返す
        r8 = concat2(r7, r7_len, (unsigned char *)&prev_state, sizeof(prev_state), &r8_len);// +4B
        r9 = concat2(r8, r8_len, t, SIG_LEN, &r9_len); // +64B
        // print_hex("r9", r9, r9_len);
        r10 = concat2(r9, r9_len, nodes[NODES-1].rand_val, sizeof(nodes[NODES-1].rand_val), &r10_len); // +4B

        unsigned char sigma_r[SIG_LEN];
        size_t sigma_r_len = SIG_LEN;

        sign_data(nodes[NODES-1].sk, r9, r9_len, sigma_r, &sigma_r_len);
        print_hex("σ_R (signature by receiver)", sigma_r, sigma_r_len);
        report = concat2(r10, r10_len, sigma_r, sigma_r_len, &report_len);
        
        // --- report を送信 ---
        // === ソケット送信 ===
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(9100);
        inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);

        if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            return 1;
        }

        uint32_t resp_len_n = htonl(report_len);
        send(sock, &resp_len_n, sizeof(resp_len_n), 0);
        send(sock, report, report_len, 0);
        close(sock);
        printf("[R] Sent report (%zu bytes) to sender\n", report_len);
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