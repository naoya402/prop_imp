#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include "func.h"

// #define PORT 9002
#define PORT 9100
#define SERVER_ADDR "127.0.0.1"


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
    // print_hex("g for τ4", g, g_len);
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

    // // uint32_t len_n;
    // // recv(client_fd, &len_n, sizeof(len_n), 0);
    // // uint32_t pkt_len = ntohl(len_n);

    // // unsigned char frame[pkt_len];
    // // recv(client_fd, frame, pkt_len, MSG_WAITALL);
    // // // close(client_fd);
    // // printf("[R] Received %u bytes from sender\n", pkt_len);
    // /* --- 応答 (暗号化) を受信 --- */
    // uint32_t resp_len_n;
    // if (recv(client_fd, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
    //     perror("recv len");
    //     close(client_fd);
    //     return 1;
    // }
    // uint32_t resp_len = ntohl(resp_len_n);
    // unsigned char *enc_resp = (unsigned char*)malloc(resp_len);
    // if (!enc_resp) { close(client_fd); return 1; }

    // if (recv(client_fd, enc_resp, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
    //     perror("recv body");
    //     free(enc_resp);
    //     close(client_fd);
    //     return 1;
    // }
    // printf("[Sender] Received (encrypted) response (%d bytes)\n", resp_len);

    // /* 復号 */
    // unsigned char *dec = NULL;
    // int dec_len = 0;
    // if (tls_decrypt(enc_resp, resp_len, &dec, &dec_len) != 0) {
    //     fprintf(stderr, "tls_decrypt failed (response)\n");
    //     free(enc_resp);
    //     close(client_fd);
    //     return 1;
    // }
    // /* dec_len は resp_len の復号後の長さ */
    // printf("[Sender] Decrypted response (%d bytes plaintext)\n", dec_len);
    // free(enc_resp);
    // free(dec);

    // // printf("[R1] Received %zu bytes\n", total_read);
    // // print_hex("Final frame", frame, pkt_len);

    // // === パース/処理 ===
    // unsigned char frame[dec_len];
    // memcpy(frame, dec, dec_len);
    // if (router_handle_forward(frame, nodes) != 0) {
    //     fprintf(stderr, "Forward processing failed\n");
    //     return 1;
    // }
    /*=======ここまで本来RPathsetup.cpp=========*/

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
    print_hex("kC_pub", kC_pub, PUB_LEN);

    //グループ署名生成
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    // groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // char *cstr = groupsig_grp_key_to_string(grpkey);
    // // printf("grpkey: %s\n", cstr);
    // groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);
    // // message_t *gsm = message_from_string((char *)kC_pub);
    // グループ署名に必要な鍵などを読み込み
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);//groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);//groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
    groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);;//groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
    // gml読み込み
    FILE *fgml = fopen("gml.dat", "rb");
    if (!fgml) die("fopen gml.dat");
    fseek(fgml, 0, SEEK_END);
    size_t gml_len = ftell(fgml);
    fseek(fgml, 0, SEEK_SET);
    unsigned char *gml_buf = (unsigned char *)malloc(gml_len);
    if (!gml_buf) die("malloc gml_buf");
    fread(gml_buf, 1, gml_len, fgml);
    fclose(fgml);
    gml_t *gml = gml_import(GROUPSIG_KTY04_CODE, gml_buf, gml_len);
    free(gml_buf);
    crl_t *crl = crl_init(GROUPSIG_KTY04_CODE);

    // Setup (new group)
    int rc = groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

    message_t *gsm = message_from_bytes(kC_pub, PUB_LEN);
    // print_hex("gsm", gsm->bytes, gsm->length);
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
    groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);

    // --- 署名をバイナリにエクスポート ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    printf("Exported signature length: %u bytes\n", sig_size);
    // print_hex("Group signature σ", sig_bytes, sig_size);

    // uint8_t valid;
    // groupsig_signature_t *gsig = groupsig_signature_import(GROUPSIG_KTY04_CODE, sig_bytes, sig_size);
    // // char *strsig2 = groupsig_signature_to_string(gsig);
    // // printf("V: gsig: %s\n", strsig2);
    // // free(strsig2);
    // groupsig_verify(&valid, gsig, gsm, grpkey);
    // printf("TGsig verification: %s\n", valid ? "valid" : "invalid");
    

    // unsigned char* にキャスト（byte_t は typedef unsigned char）
    unsigned char *uc_sig = (unsigned char *)malloc(sig_size);
    memcpy(uc_sig, sig_bytes, sig_size);
    // print_hex("Group signature σ", uc_sig, sig_size);

    size_t sid_len;
    unsigned char *sid_concat = concat2(kC_pub, PUB_LEN, sig_bytes, sig_size, &sid_len);
    // print_hex("sid", sid, sid_len);
    // hash_sid_from_pub(sid_concat, pkt.h.sid);
    hash_sid_from_pub(kC_pub, pkt.h.sid);
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
        // print_hex("ci", ci, SEG_LEN);
        // print_hex("tag", tag, TAG_LEN);
        // print_hex("iv", iv, IV_LEN);
        // // リングバッファもどき(容量=ROUTERS)に c_iやタグを循環的に挿入
        size_t offset = (size_t)((i-1) % (ROUTERS + 1)) * (SEG_LEN + TAG_LEN + IV_LEN);//ROUTERS + 1では経路長が漏洩するため適切な固定長(12など)にする

        // memcpy(pkt.h.seg_concat + offset, t2, t2_len);
        // printf("offset=%zu\n", offset);
        memcpy(pkt.h.seg_concat + offset, ci, SEG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN, tag, TAG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN + TAG_LEN, iv, IV_LEN);
        // print_hex("",pkt.h.seg_concat,MAX_SEG_CON);
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
    // print_hex("pkt.p.peer_pub", pkt.p.peer_pub, PUB_LEN);
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
    unsigned char frame[MAX_FRAME]; 
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
    // char *strsig2 = groupsig_signature_to_string(gsig);
    // printf("V: gsig: %s\n", strsig2);
    // free(strsig2);
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

    // Rによるルータの鍵交換
    for (int i = 1; i < NODES - 1; i++) {
        size_t offset = (i - 1) * PUB_LEN;
        EVP_PKEY *node_pub = import_x25519_pub(pkt.h.dh_pk_concat + offset);
        derive_shared(me->dh_sk, node_pub, sharenode);
        memcpy(me->k[i], sharenode, KEY_LEN);
        // print_hex("ki", me->k[i], KEY_LEN);
    }

    // C,Π,グループ署名を保存
    save_pi_list(pkt.h.sid, pkt.h.pi_concat, MAX_PI);
    unsigned char pi_concat[MAX_PI];
    memcpy(pi_concat, pkt.h.pi_concat, MAX_PI);
    // print_hex("R saved pi_concat", pi_concat, MAX_PI);
    printf("\n");

    // 本来はノードがRと鍵交換するのは復路だが便宜上ここで処理
    for (int i = 1; i < NODES - 1; i++) {
        // 共有鍵を計算
        Node *node = &nodes[i];
        derive_shared(node->dh_sk, nodes[NODES - 1].dh_pk, sharenode);
        // ノードiの状態に鍵を保存
        memcpy(node->ki_R, sharenode, KEY_LEN); // 復路用キーは k[ROUTERS + 1] に保存
        // printf("k%d ", i);
        // print_hex("derived ", node->k[i], KEY_LEN);
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


    // printf("\n===============================復路=================================");
    // // レシーバRの処理
    // printf("\n=== Node R(R%d) ===\n", NODES - 1);
    // US_CTX *us = US_init("secp256k1");
    
    // // ここでsidに紐づけてpi_concatを保存
    
    // //復路の経路設定パケット作成
    // memcpy(pkt.h.cid, me->state[0].precid, CID_LEN); // 往路の最後のサーキットIDを流用
    // pkt.h.status = SETUP_RESP;
    // pkt.h.idx--;
    // pkt.h.idx--; // pi_concatサイズ計算のため加算しすぎたidxをもどす
    // int preid = pkt.h.idx;
    
    // // ρ_sを生成
    // size_t rho_len = SIG_LEN;
    // unsigned char rho[SIG_LEN];
    // size_t mrho_len;
    // unsigned char *mrho= concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &mrho_len);
    // // print_hex("m for rho", mrho, mrho_len);
    // sign_data(me->sk, mrho, mrho_len, rho, &rho_len);
    // // print_hex("ρ", rho, SIG_LEN);
    // free(mrho);
    // memcpy(pkt.h.rho[(pkt.h.idx + 1) % 2], rho, SIG_LEN); // ρリストは2つ分だけ保持
    // // print_hex("ρ", (unsigned char *)pkt.h.rho, SIG_LEN*2);

    // // k_R を用意
    // unsigned char kR_pub[PUB_LEN];
    // get_raw_pub(me->dh_sk, kR_pub);
    // memcpy(pkt.p.peer_pub, kR_pub, PUB_LEN);
    // memcpy(pkt.p.rand_val, me->state[0].rand_val, sizeof(me->state[0].rand_val));

    // // US＿NIZK_Sign で A,B,s を生成
    // size_t nt_len = SIG_LEN, g2_len, nizp_len, nizk_sig_len;
    // unsigned char nt[SIG_LEN];
    // unsigned char *nizp = NULL;
    // unsigned char *nizk_sig = NULL;
    // unsigned char *g2 = concat2(sid, SID_LEN, nodes[preid].addr, 4, &g2_len);
    // // print_hex("addr", nodes[preid].addr, 4);
    // // print_hex("g", g2, g2_len);
    // sign_data(me->sk, g2, g2_len, nt, &nt_len);// 本来のτ_Rは state から取得
    // // print_hex("nt", nt, nt_len);
    // nizp = concat2(nt, nt_len, me->state[0].rand_val, sizeof(me->state[0].rand_val), &nizp_len);// 本来の乱数は state から取得
    // // print_hex("nizp", nizp, nizp_len);
    // // π_i を取り出す
    // size_t offset_cur = preid * USIG_LEN;
    // if (offset_cur + USIG_LEN > MAX_PI) { 
    //     fprintf(stderr,"pi_concat out of range\n"); 
    //     return -1; 
    // }
    // unsigned char *pi_cur = pkt.h.pi_concat + offset_cur;
    // // print_hex("pi_cur", pi_cur, USIG_LEN);
    // int ver = US_NIZK_Sign(us, nizp, nizp_len, me->us_x, me->us_y, pi_cur, USIG_LEN, &nizk_sig, &nizk_sig_len);
    // if (!ver) { fprintf(stderr,"US_NIZK_Sign error at R%d\n", idx); return 1; }
    // pkt.p.nizk_sig_len = nizk_sig_len;
    // // printf("nizk_sig_len: %zu\n", nizk_sig_len);
    // pkt.p.nizk_sig = (unsigned char *)malloc(nizk_sig_len);
    // memcpy(pkt.p.nizk_sig, nizk_sig, nizk_sig_len);
    // // print_hex("nizk_sig", nizk_sig, nizk_sig_len);
    // free(nizp);
    // free(nizk_sig);
    // free(g2);


    // // ==== SETUP_RESP をパケットに積む（DST_S と pi_concat を格納）====
    // // 復路の送信フレームを作成
    // memset(frame, 0, sizeof(frame));
    // write_l2l3_min(frame, sizeof(frame));
    // // print_hex("SID(R)", pkt.h.sid, SID_LEN);
    // // size_t 
    // wire_len = build_overlay_setup_resp(frame, sizeof(frame), &pkt);
    // printf("R sending SETUP_RESP (%zu bytes)\n", wire_len);

    // // 各ノードの処理
    // // 復路は逆順に転送
    // // int cur = nodes[ROUTERS].id;
    // for (int i = ROUTERS; i >= 0; i--) {
    //     if (router_handle_reverse(frame, nodes) != 0) die("reverse fail");
    //     // Node *curN = &nodes[cur];
    //     // cur = state_get_prev(curN, pkt.h.sid);
    // }

    // // センダーSの処理
    // if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
    //     fprintf(stderr, "S: parse failed\n");
    //     // free(pkt);
    //     return -1;
    // }
    // // Sもkを計算
    // me = &nodes[0];
    // EVP_PKEY *R_pub = import_x25519_pub(pkt.p.peer_pub);
    // unsigned char kC_shared[SEC_LEN];
    // derive_shared(me->dh_sk, R_pub, kC_shared);
    // EVP_PKEY_free(R_pub);

    // memcpy(me->sess_key, kC_shared, KEY_LEN);
    // me->has_sess = 1;
    // print_hex("S derived k", me->sess_key, KEY_LEN);

    // // // PKIから生成した鍵と同じか確認
    // // if (memcmp(me->sess_key, nodes[0].k[NODES-1], KEY_LEN) != 0) {
    // //     die("k mismatch");
    // // }
    // puts("== 経路設定完了・セッション確立 ==");

    printf("\n======= データ転送フェーズ =======\n");
    const char *msg = "hello world";
    size_t msg_len = strlen(msg);
    printf("S sending plaintext: %s\n", msg);

    // --- Padding Fix: 先頭にゼロブロックを付加 ---
    #define PAD_LEN 32  // PAD_LEN*8 bit分のパディング 1ブロック=128bit
    unsigned char zero_pad[PAD_LEN] = {0};

    size_t padded_len = 0;
    unsigned char *padded_msg = concat2(zero_pad, PAD_LEN,(const unsigned char*)msg, msg_len,&padded_len);
    // print_hex("Padded message", padded_msg, padded_len);


    // Sの処理: msgを暗号化して送信パケット作成
    printf("S -> ");
    unsigned char sid_use[SID_LEN];
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(me->dh_sk, kS_pub);
    hash_sid_from_pub(kS_pub, sid_use);
    memcpy(pkt.h.sid, sid_use, SID_LEN);

    pkt.h.status = DATA_TRANS;

       
    // aead_encrypt(nodes[0].sess_key, (const unsigned char*)msg, msg_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    // pkt.p.ct_len = msg_len;
    // print_hex("S sess_key", nodes[0].sess_key, KEY_LEN);
    aead_encrypt(nodes[0].sess_key, padded_msg, padded_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = padded_len;
    free(padded_msg);

    //センダーのMAC
    // 各ノードの共有鍵 k_i を計算 & c_i を生成
    for (int i = 1; i < NODES - 1; i++) {
        // print_hex("ki", me->k[i], KEY_LEN);
        // HMACでACSEG生成
        unsigned char acseg[ACSEG_LEN];
        unsigned int acseg_len;
        size_t offset = (i - 1) * ACSEG_LEN;
        // print_hex("me->ki", me->ki, KEY_LEN);
        int hmac_result = hmac_sha256(me->k[i], KEY_LEN, pkt.p.ct, pkt.p.ct_len, pkt.h.acseg_concat + offset, &acseg_len);
        if (hmac_result != 0) {
            fprintf(stderr,"HMAC failed at R%d\n", idx);
            return -1;
        }
    }
    // print_hex("ACSEG concat", pkt.h.acseg_concat, ROUTERS * ACSEG_LEN);
    
    pkt.h.idx = 1;
    // ==== DATA_TRANS をパケットに積む ====
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);
    printf("Data Trans frame wire_len=%zu \n", wire_len);

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
    
    // Rの処理: MAC確認＆復号
    printf("R(R%d)\n", cur);
    me = &nodes[NODES-1];
    unsigned char padplain[MAX_PTXT];
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "R: parse failed\n");
        return -1;
    }

    // MAC確認
    int t_flag = 0;
    for (int i = 1; i < NODES - 1; i++) {
        unsigned char *acseg = (unsigned char *)malloc(ACSEG_LEN);
        unsigned int acseg_len;
        unsigned char *ac_plain2; size_t ac_plain2_len;
        size_t offset = (i - 1) * ACSEG_LEN;
        ac_plain2 = concat2(pkt.h.acseg_concat, (i - 1) * ACSEG_LEN, pkt.p.ct, pkt.p.ct_len, &ac_plain2_len);
        // print_hex("AC Plain", ac_plain2, ac_plain2_len);
        int hmac_result = hmac_sha256(me->k[i], KEY_LEN, ac_plain2, ac_plain2_len, acseg, &acseg_len);
        int flags = 0; // すべて一致なら1
        // acseg_concat内の自身のacsegと比較
        // print_hex("Received ACSEG", pkt.h.acseg_concat + offset, ACSEG_LEN);
        if (memcmp(acseg, pkt.h.acseg_concat + offset, ACSEG_LEN) == 0) {
            // printf("R%d ACSEG match\n", i);
            flags = 1;
        } else {
            printf("R%d ACSEG mismatch\n", i);
        }
        t_flag += flags;
        free(acseg);
    }
    if (t_flag <= ROUTERS/2) {
        fprintf(stderr, "ACSEG mismatch\n");
    } else {
        printf("All ACSEGs match\n");
    }

    // 復号
    if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, padplain))
        die("GCM auth fail at R");

    // --- Padding Fix: 先頭のゼロブロック確認 ---
    int zero_ok = 1;
    for (size_t i = 0; i < PAD_LEN; i++) {
        if (padplain[i] != 0) { zero_ok = 0; break; }
    }
    if (!zero_ok) {
        fprintf(stderr, "Key-commitment verification failed\n");
    }
    // 実際のメッセージ部分抽出
    size_t real_len = padded_len - PAD_LEN;
    unsigned char *real_msg = padplain + PAD_LEN;

    printf("R(R%d) got plaintext: %.*s\n", cur, (int)real_len, (char *)real_msg);
    
    int blocked = apply_policy_contract((const char *)real_msg);
    
    if (blocked) {
        printf("\n======= 責任追跡フェーズ =======\n");
        US_CTX *us = US_init("secp256k1");
        if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
        // 通報用ビルド
        wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);
        // Rの処理
        // トラフィックを通報
        // 本来は保存したS_pubとsigを使う
        // 以下の要素をすべて連結 sig_lenとpkt_len
        // S_pub,sig,pkt,plain,node[NODES-1].sess_key,com_concat,pi_concat,dh_pk_concat,state_get_prev(me.pkt.h.sid),τ, v, sigma_s
        size_t r1_len, r2_len, r3_len, r4_len, r5_len, r6_len, r7_len, r8_len, r9_len, r10_len, r11_len, r12_len, r13_len, report_len;
        unsigned char *r1=NULL, *r2=NULL, *r3=NULL, *r4=NULL, *r5=NULL, *r6=NULL, *r7=NULL,*r8=NULL,*r9=NULL,*r10=NULL,*r11=NULL,*r12=NULL,*r13=NULL, *report=NULL;

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
        // print_hex("Exported signature σ", sig_bytes, sig_size);
        
        size_t l2l3_len = write_l2l3_min(frame, sizeof(frame));
        size_t total_len = l2l3_len + wire_len;
        // printf("total_len: %zu\n", total_len);
        
        //NIZK用のvを生成
        size_t n2_len, nn2_len;
        unsigned char *n2 = concat2(pkt.h.com_concat, MAX_PI, pkt.h.pi_concat, ROUTERS * USIG_LEN, &n2_len);
        unsigned char *nn2 = concat2(pkt.h.dh_pk_concat, ROUTERS * PUB_LEN, n2, n2_len, &nn2_len);
        // print_hex("nn2", nn2, nn2_len);
        size_t v2_len; // sufficient size
        unsigned char *v2 = (unsigned char *)malloc(32 *3 + 33 * 2);
        //最後のpi_concatを抽出
        // print_hex("pi_concat", pi_concat, MAX_PI);
        unsigned char *USpi = pkt.h.pi_concat + ROUTERS * USIG_LEN;
        // print_hex("USpi", USpi, USIG_LEN);
        int ver = US_NIZK_Confirm(us, nn2, nn2_len, me->us_x, me->us_y, USpi , USIG_LEN, &v2, &v2_len);// 本来2つ目は次ノードの公開鍵
        if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
        // print_hex("v2", v2, v2_len);
        
        r1 = concat2(kS_pub, PUB_LEN, (unsigned char *)&sig_size, sizeof(sig_size), &r1_len);// 32 + 4B
        // print_hex("r1", r1, r1_len);
        r2 = concat2(r1, r1_len, (unsigned char *)sig_bytes, sig_size, &r2_len);// +2034B
        // print_hex("r2", r2, r2_len);
        // printf("wire_len: %lu\n", wire_len);
        r3 = concat2(r2, r2_len, (unsigned char *)&total_len, sizeof(total_len), &r3_len);// +8B
        // print_hex("r3", r3, r3_len);
        r4 = concat2(r3, r3_len, frame, total_len, &r4_len); // 34 + 267B(アカセグ付き)
        // print_hex("r4", r4, r4_len);
        r5 = concat2(r4, r4_len, real_msg, (int)real_len, &r5_len); // +11B
        r6 = concat2(r5, r5_len, nodes[NODES-1].sess_key, KEY_LEN, &r6_len); // +32B
        r7 = concat2(r6, r6_len, pkt.h.com_concat, MAX_PI, &r7_len);// 132B
        r8 = concat2(r7, r7_len, pkt.h.pi_concat, MAX_PI, &r8_len);// 132B N2からN5
        r9 = concat2(r8, r8_len, pkt.h.dh_pk_concat, ROUTERS * PUB_LEN, &r9_len);// 128B
        // print_hex("r9", r9, r9_len);
        int prev_state = ROUTERS;//state_get_prev(me, pkt.h.sid); //本来アドレスを返す
        r10 = concat2(r9, r9_len, (unsigned char *)&prev_state, sizeof(prev_state), &r10_len);// +4B
        r11 = concat2(r10, r10_len, t, SIG_LEN, &r11_len); // +64B
        // print_hex("τ4", t, SIG_LEN);
        r12 = concat2(r11, r11_len, nodes[NODES-1].state[0].rand_val, sizeof(nodes[NODES-1].state[0].rand_val), &r12_len); // +4B
        // print_hex("r12", r12, r12_len);
        r13 = concat2(r12, r12_len, v2, v2_len, &r13_len); // + 162B

        unsigned char sigma_r[SIG_LEN];
        size_t sigma_r_len = SIG_LEN;

        sign_data(nodes[NODES-1].sk, r13, r13_len, sigma_r, &sigma_r_len);
        print_hex("σ_R (signature by receiver)", sigma_r, sigma_r_len);
        report = concat2(r13, r13_len, sigma_r, sigma_r_len, &report_len);
        
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

        // uint32_t resp_len_n = htonl(report_len);
        // send(sock, &resp_len_n, sizeof(resp_len_n), 0);
        // send(sock, report, report_len, 0);
        // close(sock);
        // printf("[R] Sent report (%zu bytes) to sender\n", report_len);

        /* --- 暗号化して送信 --- */
        unsigned char *enc = NULL;
        int enc_len = 0;
        if (tls_encrypt(report, report_len, &enc, &enc_len) != 0) {
            fprintf(stderr, "tls_encrypt failed\n");
            close(sock);
            return 1;
        }
        uint32_t enc_len_n = htonl((uint32_t)enc_len);
        send(sock, &enc_len_n, sizeof(enc_len_n), 0);
        send(sock, enc, enc_len, 0);
        printf("[Receiver] Sent (encrypted) report (%d bytes ciphertext + tag)\n", enc_len);
        free(enc);
        // print_hex("Encrypted report", enc, enc_len);


        free(r1); free(r2); free(r3); free(r4); free(r5); free(r6); free(r7); free(r8); free(r9);
        

    }
        
    
    // // === DPDKで次ノードへ送信 ===//いらんくね？
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
    // groupsig_signature_free(gsig);
    // groupsig_mem_key_free(memkey);
    // groupsig_grp_key_free(grpkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);

    // free(sig_bytes);
    // free(sid);
    return 0;
}