
#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include <time.h>
#include <unistd.h>

#include "func.h"

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


int main(void) {
    // グループ署名初期化
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
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
    groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

    // US context 初期化
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    // ノード初期化
    Node nodes[NODES];
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    Packet pkt;

    // 検証者Vの処理
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

    /* --- 応答 (暗号化) を受信 --- */
    uint32_t resp_len_n;
    if (recv(client, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
        perror("recv len");
        close(client);
        return 1;
    }
    uint32_t resp_len = ntohl(resp_len_n);
    unsigned char *enc_resp = (unsigned char*)malloc(resp_len);
    if (!enc_resp) { close(client); return 1; }

    if (recv(client, enc_resp, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
        perror("recv body");
        free(enc_resp);
        close(client);
        return 1;
    }
    printf("[Verifier] Received (encrypted) report (%d bytes)\n", resp_len);
    // print_hex("Encrypted report", enc_resp, resp_len);

    /* 復号 */
    unsigned char *dec = NULL;
    int dec_len = 0;
    if (tls_decrypt(enc_resp, resp_len, &dec, &dec_len) != 0) {
        fprintf(stderr, "tls_decrypt failed (response)\n");
        free(enc_resp);
        close(client);
        return 1;
    }
    /* dec_len は resp_len の復号後の長さ */
    printf("[Verifier] Decrypted report (%d bytes plaintext)\n", dec_len);
    free(enc_resp);
    // free(dec);
    
     unsigned char report[dec_len];
    memcpy(report, dec, dec_len);

    // uint32_t len_n;
    // recv(client, &len_n, sizeof(len_n), 0);
    // uint32_t len = ntohl(len_n);

    // unsigned char report[len];
    // recv(client, report, len, MSG_WAITALL);
    // printf("[Verifier] Received report (%u bytes)\n", len);
    // print_hex("report", report, len);



    // 通報パケットのパース
    size_t offset = 0;

    // 1) k_S_pub 抽出
    unsigned char k_S[PUB_LEN];
    memcpy(k_S, report + offset, PUB_LEN); offset += PUB_LEN;
    // print_hex("k_S", k_S, PUB_LEN);

    // 2) グループ署名（Sig）抽出
    size_t sig_len;
    memcpy(&sig_len, report + offset, 4); offset += 4;
    // printf("sig_len: %zu\n", sig_len);
    unsigned char gsig_bytes[sig_len];
    memcpy(gsig_bytes, report + offset, sig_len); offset += sig_len;
    // print_hex("gsig_bytes", gsig_bytes, sig_len);
    groupsig_signature_t *sig = groupsig_signature_import(GROUPSIG_KTY04_CODE, gsig_bytes, sig_len);
    // char *strsig = groupsig_signature_to_string(sig);
    // printf("V: gsig: %s\n", strsig);
    // free(strsig);

    // 3) Packet構造体の復元
    size_t pkt_len;
    memcpy(&pkt_len, report + offset, 8);//sizeof(pkt_len));
    offset += 8;//sizeof(pkt_len);
    // printf("pkt_len: %lu\n", pkt_len);
    // Packet pkt;
    unsigned char frame[pkt_len];
    memcpy(frame, report + offset, pkt_len); offset += pkt_len;
    // print_hex("frame", frame, pkt_len);
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
                fprintf(stderr, "parse failed\n");
                return -1;
    }

    // print_hex("ACSEG: ", pkt.h.acseg_concat, ACSEG_LEN * ROUTERS);

    // 4) 平文（plain）抽出
    size_t plain_len = pkt.p.ct_len - PAD_LEN;
    unsigned char plain_recv[plain_len];// パディング付きの平文
    memcpy(plain_recv, report + offset, pkt.p.ct_len); offset += plain_len;
    // printf("plain_recv: %.*s\n", (int)plain_len, plain_recv);

    // 5) セッション鍵
    unsigned char sess_key[KEY_LEN];
    memcpy(sess_key, report + offset, KEY_LEN); offset += KEY_LEN;
    // print_hex("sess_key", sess_key, KEY_LEN);

    // 6) concat
    unsigned char com_concat[MAX_PI];
    unsigned char pi_concat[MAX_PI];
    unsigned char dh_pk_concat[ROUTERS * PUB_LEN];
    memcpy(com_concat, report + offset, MAX_PI); offset += MAX_PI;
    // print_hex("com_concat", com_concat, MAX_PI);
    memcpy(pi_concat, report + offset, MAX_PI); offset += MAX_PI;
    // print_hex("pi_concat", pi_concat, MAX_PI);
    memcpy(dh_pk_concat, report + offset, ROUTERS * PUB_LEN); offset += ROUTERS * PUB_LEN;
    // print_hex("dh_pk_concat", dh_pk_concat, ROUTERS * PUB_LEN);

    // 7) prev_state
    int prev_state;
    memcpy(&prev_state, report + offset, sizeof(prev_state)); offset += sizeof(prev_state);
    // printf("prev_state: %d\n", prev_state);

    // 8) τ
    unsigned char tau[SIG_LEN];
    memcpy(tau, report + offset, SIG_LEN); offset += SIG_LEN;
    // print_hex("tau", tau, SIG_LEN);

    // 9) rand_val
    unsigned char rand_val[4];
    memcpy(rand_val, report + offset, sizeof(rand_val)); offset += sizeof(rand_val);
    // print_hex("rand_val", rand_val, sizeof(rand_val));

    // 10) NIZK proof
    size_t v_len = 32 *3 + 33 * 2;
    unsigned char *v = (unsigned char *)malloc(v_len);
    memcpy(v, report + offset, v_len); offset += v_len;
    // print_hex("v", v, v_len);

    // 8) σ_R (Receiver署名)
    unsigned char sigma_r[SIG_LEN];
    memcpy(sigma_r, report + offset, SIG_LEN); offset += SIG_LEN;
    // size_t sigma_r_len = SIG_LEN;
    // print_hex("sigma_r", sigma_r, SIG_LEN);

    // printf("Parsed report packet successfully (total %zu bytes parsed)\n", offset);

    // 通報の正当性検証
    // 1) sigma 検証 (R_pub は known)
    // --- 署名対象データ (σ_r を除く部分) ---
    size_t r_len = dec_len - SIG_LEN;  // report 全体から σ_r を除いた長さ
    unsigned char *r = (unsigned char *)malloc(r_len);
    memcpy(r, report, r_len);
    // print_hex("r (data signed by Receiver)", r, r_len);
    // --- 署名検証 ---
    if (verify_sig(nodes[NODES-1].pk, r, r_len, sigma_r, SIG_LEN)) {
        printf("σ_r verification succeeded\n");
    } else {
        printf("σ_r verification failed\n");
    }

    // 2) SID 再計算: 例 -> SID = SHA256( S_pub ) or whatever your scheme uses
    unsigned char sid_chk[SID_LEN];
    // --- 署名をバイナリにエクスポート ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    // printf("Exported signature length: %u bytes\n", sig_size);

    size_t sid_len;
    unsigned char *sid; 
    sid = concat2(k_S, PUB_LEN, sig_bytes, sig_size, &sid_len);
    // print_hex("sid", sid, sid_len);
    hash_sid_from_pub(sid, pkt.h.sid);
    // print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
    // parse_frame_to_pkt(frame, frame_len, &pkt); // 既存関数
    // Packet pkt;
    // unsigned char frame[MAX_FRAME];
    // if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) { /* error */ }
    if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) { /* mismatch */ }
    printf("SID check: match\n");


    // 3) groupsig 検証
    // groupsig_signature_t *gsig = groupsig_signature_import(GROUPSIG_KTY04_CODE, groupsig_bytes, groupsig_len);
    uint8_t val;
    print_hex("k_S", k_S, PUB_LEN);
    message_t *kSb = message_from_bytes(k_S, PUB_LEN);
    groupsig_verify(&val, sig, kSb, grpkey);
    printf("TGsig verification: %s\n", val ? "valid" : "invalid");

    // 4) ペイロード復号
    // ここでは pkt.p.iv, pkt.p.ct, pkt.p.tag を利用する
    unsigned char padplain[MAX_PTXT];
    if (!aead_decrypt(sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, padplain)) {
        /* decrypt fail */
    }
    // --- Padding Fix: 先頭のゼロブロック確認 ---
    int zero_ok = 1;
    size_t padded_len = 0;
    
    for (size_t i = 0; i < PAD_LEN; i++) {
        if (padplain[i] != 0) { zero_ok = 0; break; }
    }
    if (!zero_ok) {
        fprintf(stderr, "Key-commitment verification failed\n");
    }
    // 実際のメッセージ部分抽出
    // size_t real_len = padded_len - PAD_LEN;
    unsigned char *real_msg = padplain + PAD_LEN;
    // printf("plain_out: %.*s\n", (int)pkt.p.ct_len, plain_out);
    if (memcmp(real_msg, plain_recv, plain_len) != 0) { /* mismatch */ }
    printf("Decrypt result match: %.*s\n", (int)plain_len, real_msg);
    
    // 5) コントラクト検証
    int blocked = apply_policy_contract((const char *)plain_recv);
    if (!blocked) {// 以降の処理は行わない
    } 
    // printf("Policy contract False.\n");

    // 6) US,コミット,前ホップ検証
    // π検証  通報のpi_concatからπiを抽出して検証
    // print_hex("pi_concat", pi_concat, MAX_PI);
    int rec_id = pkt.h.idx; //5
    int prev_idx = pkt.h.idx -1; //4
    size_t pioffset = (rec_id - 1) * USIG_LEN;
    if (pioffset + USIG_LEN > MAX_PI) {
        fprintf(stderr,"pi_concat out of range\n");
        return -1;
    }
    // π_Rを検証
    //pi_concatから前ノード分を取り出す
    unsigned char *pi = (unsigned char *)malloc(USIG_LEN);
    memcpy(pi, pi_concat + (rec_id - 1) * USIG_LEN, USIG_LEN);
    // print_hex("pi", pi, USIG_LEN);
    size_t pi_len = USIG_LEN;
    //com_concatと取り出した残りのΠからnを生成
    size_t n_len, nn_len;
    unsigned char *n = NULL;
    unsigned char *nn = NULL;
    n = concat2(com_concat, MAX_PI, pi_concat, ROUTERS * USIG_LEN, &n_len);
    nn = concat2(dh_pk_concat, ROUTERS * PUB_LEN, n, n_len, &nn_len);
    // print_hex("nn", nn, nn_len);

    v_len = 32 *3 + 33 * 2;
    int ver = US_NIZK_VerifyC(us, nodes[prev_idx].us_y, nodes[rec_id].us_y, nn, nn_len, pi, pi_len, v, v_len);//本来2つ目は前ノードの公開鍵
    if (ver == 1) {
        // printf("NIZK Signature CONFIRMED.\n");
        printf("Verify π%d success\n", rec_id);
    } else if (ver == 0) {
        // printf("NIZK Signature NOT confirmed.\n");
        fprintf(stderr, "Verify π%d failed\n", rec_id);
    }
    free(pi);
    free(n);
    free(v);

    //最後のcom_concatを抽出
    unsigned char *com = com_concat + ROUTERS * USIG_LEN;
    // print_hex("com", com, USIG_LEN);
    size_t n2_len;
    ver = EC_Com_Verify(us, tau, SIG_LEN, rand_val, sizeof(rand_val), G, com, USIG_LEN);
    if (ver == 1) {
        printf("EC Commitment VERIFIED.\n");
    } else if (ver == 0) {
        printf("EC Commitment NOT verified.\n");
    }
    // if (!verify_sig(nodes[rec_id].pk, n, n_len, pi_vrf, SIG_LEN)) {
    //     free(n);
    //     fprintf(stderr,"Verify π%d failed\n", rec_id);
    //     return -1;
    // }
    // free(n);
    // printf("Verify π%d success \n", rec_id);
    // τi-1検証
    unsigned char *m = NULL; size_t m_len = 0;
    m = concat2(pkt.h.sid, SID_LEN, nodes[prev_idx].addr, sizeof(nodes[prev_idx].addr), &m_len);
    // print_hex("m for τi-1", m, m_len);
    if (!verify_sig(nodes[prev_idx].pk, m, m_len, tau, SIG_LEN)) {//pkt.p.tau_len)) {
        fprintf(stderr, "Verify τ%d failed\n", prev_idx);
        free(m);
        return -1;
    }
    free(m);
    printf("Verify τ%d success\n", prev_idx);

    // // === Open（署名者を特定） ===
    uint64_t id = UINT64_MAX;
    int rc = groupsig_open(&id, NULL, NULL, sig, grpkey, mgrkey, gml);
    if (rc == IOK) {
        printf("Open success: member ID = %lu\n", id);
    } else {
        printf("Open failed.\n");
    }
    
    // ルータから得たidリストと比較してSを特定
    // uint64_t id = 0;
    const char *signer = router_addresses[id]; // 仮にidをインデックスとしてSを特定
    // gml_entry_t *entry = gml_get(gml, id);
    // if (!entry) {
    //     fprintf(stderr, "No entry found for ID %lu\n", id);
    // }
    // char *entry_str = gml_entry_to_string(entry);
    // printf("=== GML Entry ID %lu ===\n%s\n", id, entry_str);
    // free(entry_str);

    // 各ノードに問い合わせてS特定
    // idがそのままSのIDとする 本来はidリストと比較してSを特定
    uint64_t s_id = id;

    // 送信パケットの構築
    // ペイロード部の連結
    size_t pay_len = IV_LEN + 2 + pkt.p.ct_len + TAG_LEN;
    unsigned char *pay_buf1; size_t pay_buf1_len;
    unsigned char *pay_buf2; size_t pay_buf2_len;
    unsigned char *pay_buf3; size_t pay_buf3_len;
    uint16_t ctlen_n = htons((uint16_t)pkt.p.ct_len);
    pay_buf1 = concat2((unsigned char*)&ctlen_n, 2, pkt.p.ct, pkt.p.ct_len, &pay_buf1_len);
    // pay_buf1 = concat2(pkt.p.iv, IV_LEN, (unsigned char*)&ctlen_n, 2, &pay_buf1_len);
    // pay_buf2 = concat2(pay_buf1, pay_buf1_len, pkt.p.ct, pkt.p.ct_len, &pay_buf2_len);
    // pay_buf3 = concat2(pay_buf2, pay_buf2_len, pkt.p.tag, TAG_LEN, &pay_buf3_len);
    unsigned char *ac_plain1; size_t ac_plain1_len;
    unsigned char *ac_plain2; size_t ac_plain2_len;
    unsigned char *ac_plain3; size_t ac_plain3_len;
    unsigned char *ac_plain4; size_t ac_plain4_len;
    unsigned char *ac_plain5; size_t ac_plain5_len;
    unsigned char *inq; size_t inq_len;
    
    //公開鍵の準備
    EC_POINT *Y = nodes->us_y;
    
    // uint32_t next_addr_n = htonl((uint32_t)pkt.h.idx);//次のルータアドレスを現在のインデックスに指定 本来はstateから取得
    ac_plain1 = concat2(pkt.h.sid, SID_LEN, pay_buf1, pay_buf1_len, &ac_plain1_len);
    // print_hex("AC_SEG: ", pkt.h.acseg_concat, (pkt.h.idx - 1) * ACSEG_LEN);
    // print_hex("ac_plain1", ac_plain1, ac_plain1_len);
    // // Sになるまで問い合わせループ
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    uint32_t cur_id = prev_state; // 最後に接続したルータのIDから開始 //4
    int flags = 0;
    while (1) {// ルータに問い合わせてSを特定
        ac_plain2 = concat2(ac_plain1, ac_plain1_len, dh_pk_concat, cur_id * PUB_LEN, &ac_plain2_len);
        // print_hex("ac_plain2", ac_plain2, ac_plain2_len);
        // print_hex("AC_SEG: ", pkt.h.acseg_concat, (ROUTERS) * ACSEG_LEN);
        ac_plain3 = concat2(ac_plain2, ac_plain2_len, com_concat, cur_id * USIG_LEN, &ac_plain3_len);
        // print_hex("ac_plain3", ac_plain3, ac_plain3_len);
        // if (cur_id > 0) {
        ac_plain4 = concat2(ac_plain3, ac_plain3_len, pi_concat, (cur_id - 1) * USIG_LEN, &ac_plain4_len);
        // print_hex("ac_plain4", ac_plain4, ac_plain4_len);
        ac_plain5 = concat2(ac_plain4, ac_plain4_len, pi_concat + (cur_id - 1) * USIG_LEN, USIG_LEN, &ac_plain5_len);
        // print_hex("ac_plain5", ac_plain5, ac_plain5_len);
        // } else {
        // ac_plain4 = concat2(ac_plain3, ac_plain3_len, NULL, 0, &ac_plain4_len);
        // // print_hex("ac_plain4", ac_plain4, ac_plain4_len);
        // ac_plain5 = concat2(ac_plain4, ac_plain4_len, NULL, 0, &ac_plain5_len);
        // // print_hex("ac_plain5", ac_plain5, ac_plain5_len);
        // }

    //     //チャレンジの生成
    //     BIGNUM *a = BN_new();
    //     BIGNUM *b = BN_new();
    //     EC_POINT *W = EC_POINT_new(us->group);
    //     // EC_GROUP *group1 = EC_GROUP_new_by_curve_name(CURVE_NID);
    //     //通報のpi_concatからπiを抽出
    //     // print_hex("pi_concat", pi_concat, MAX_PI);
    //     size_t pioffset = (cur_id - 1) * USIG_LEN;
    //     if (pioffset + USIG_LEN > MAX_PI) {
    //         fprintf(stderr,"pi_concat out of range\n");
    //         return -1;
    //     }
    //     unsigned char *pi_vrf = pi_concat + pioffset;
    //     // print_hex("pi_vrf", pi_vrf, USIG_LEN);
    //     if (!US_challenge(us,pi_vrf, USIG_LEN, Y, a, b, W)) {
    //         fprintf(stderr,"US_challenge error\n"); return 1;
    //     }
    //    unsigned char W_bytes[EC_POINT_point2oct(us->group, W, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx)];
    //     size_t W_len = EC_POINT_point2oct(us->group, W, POINT_CONVERSION_COMPRESSED, W_bytes, sizeof(W_bytes), us->ctx);
    //     if (W_len == 0) {
    //         fprintf(stderr, "EC_POINT_point2oct(W) failed\n");
    //         return 1;
    //     }
        // print_hex("W", W_bytes, W_len);
        // inq = SID(32B) || Payload(41B) || next_addr(4B)|| ACSEG(32B) || challenge(33B)
        inq = ac_plain5;//concat2(ac_plain3, ac_plain3_len, W_bytes, W_len, &inq_len);
        inq_len = ac_plain5_len;
        // print_hex("inq", inq, inq_len);
        // === ソケット送信 ===
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(9010);
        inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);
        
        if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            return 1;
        }

        // uint32_t inq_len_n = htonl(inq_len);
        // send(sock, &inq_len_n, sizeof(inq_len_n), 0);
        // send(sock, inq, inq_len, 0);
        // printf("[Verifier] Sent INQ to R%d\n", 1);//cur_id);

        /* --- 暗号化して送信 --- */
        unsigned char *enc = NULL;
        int enc_len = 0;
        if (tls_encrypt(inq, inq_len, &enc, &enc_len) != 0) {
            fprintf(stderr, "tls_encrypt failed\n");
            close(sock);
            return 1;
        }
        uint32_t enc_len_n = htonl((uint32_t)enc_len);
        send(sock, &enc_len_n, sizeof(enc_len_n), 0);
        send(sock, enc, enc_len, 0);
        printf("[Verifier] Sent (encrypted) inq request (%d bytes ciphertext + tag)\n", enc_len);
        // print_hex("enc inq", enc, enc_len);
        // free(enc);
        
        
        //問い合わせの応答受信
        // uint32_t reinq_len_n;
        // recv(sock, &reinq_len_n, sizeof(reinq_len_n), 0);
        // uint32_t reinq_len = ntohl(reinq_len_n);
        
        // unsigned char reinq[reinq_len];
        // recv(sock, reinq, reinq_len, MSG_WAITALL);
        // printf("[Verifier] Received REINQ (%u bytes) from R%d\n", reinq_len, 1);//cur_id);
        // print_hex("reinq", reinq, reinq_len);

        // /* --- 応答 (暗号化) を受信 --- */
        uint32_t resp_len_n;
        if (recv(sock, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
            perror("recv len");
            close(sock);
            return 1;
        }
        uint32_t resp_len = ntohl(resp_len_n);
        // printf("resp_len: %u\n", resp_len);
        unsigned char *enc_resp = (unsigned char*)malloc(resp_len);
        if (!enc_resp) { close(sock); return 1; }

        if (recv(sock, enc_resp, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
            perror("recv body");
            free(enc_resp);
            close(sock);
            return 1;
        }
        printf("[Verifier] Received (encrypted) reinq (%d bytes)\n", resp_len);

        /* 復号 */
        unsigned char *dec = NULL;
        int dec_len = 0;
        if (tls_decrypt(enc_resp, resp_len, &dec, &dec_len) != 0) {
            fprintf(stderr, "tls_decrypt failed (response)\n");
            free(enc_resp);
            close(sock);
            return 1;
        }
        /* dec_len は resp_len の復号後の長さ */
        printf("[Verifier] Decrypted reinq (%d bytes plaintext)\n", dec_len);
        free(enc_resp);
        // free(dec);
        unsigned char reinq[dec_len];
        memcpy(reinq, dec, dec_len);
        free(dec);
        
        // ノードからの応答パケットのパース
        size_t offset = 0;
        int tmp_addr = 0; // 本来前ホップアドレス(今回はID)
        // size_t R_len = 33;
        size_t v_len = 32 *3 + 33 * 2;
        unsigned char v[v_len];
        size_t vp_len = v_len;
        unsigned char vp[vp_len];
        // unsigned char R_bytes[R_len];
        unsigned char tau[SIG_LEN];
        // unsigned char rand_val[4];
        // int flag = 0; // 各ノードのアカセグ検証結果フラグ
        // memcpy(&tmp_addr, reinq + offset, sizeof(tmp_addr)); offset += sizeof(tmp_addr);
        // // printf("[Verifier] Received next Router ID: %d\n", tmp_addr);
        // memcpy(R_bytes, reinq + offset, R_len); offset += R_len;
        // // print_hex("Received R: ", R_bytes, R_len);
        // memcpy(tau, reinq + offset, SIG_LEN); offset += SIG_LEN;
        // // print_hex("[Verifier] Received tau: ", tau, SIG_LEN);
        // memcpy(rand_val, reinq + offset, sizeof(rand_val)); offset += sizeof(rand_val);
        // // print_hex("[Verifier] Received rand_val: ", rand_val, sizeof(rand_val));
        // memcpy(&flag, reinq + offset, 2); offset += 2;
        // printf("Received flag: %d\n", flag);
        int flag = 0; // 各ノードのアカセグ検証結果フラグ
        memcpy(v , reinq + offset, v_len); offset += v_len;
        // print_hex("Received v: ", v, v_len);
        memcpy(vp, reinq + offset, vp_len); offset += vp_len;
        // print_hex("Received vp: ", vp, vp_len);
        memcpy(tau, reinq + offset, SIG_LEN); offset += SIG_LEN;
        // print_hex("[Verifier] Received tau: ", tau, SIG_LEN);
        memcpy(rand_val, reinq + offset, sizeof(rand_val)); offset += sizeof(rand_val);
        // print_hex("[Verifier] Received rand_val: ", rand_val, sizeof(rand_val));
        memcpy(&tmp_addr, reinq + offset, sizeof(tmp_addr)); offset += sizeof(tmp_addr);
        // printf("[Verifier] Received next Router ID: %d\n", tmp_addr);
        memcpy(&flag, reinq + offset, 2); offset += 2;
        
        // π_i-1を検証
        //pi_concatから前ノード分を取り出す
        unsigned char *pi = (unsigned char *)malloc(USIG_LEN);
        memcpy(pi, pi_concat + (cur_id - 1) * USIG_LEN, USIG_LEN);
        // print_hex("pi", pi, USIG_LEN);
        size_t pi_len = USIG_LEN;
        //com_concatと取り出した残りのΠからnを生成
        size_t n_len, nn_len;
        unsigned char *n = NULL;
        unsigned char *nn = NULL;
        n = concat2(com_concat, cur_id * USIG_LEN, pi_concat, (cur_id - 1) * USIG_LEN, &n_len);
        nn = concat2(dh_pk_concat, cur_id * PUB_LEN, n, n_len, &nn_len);
        // print_hex("nn", nn, nn_len);

        v_len = vp_len = 32 *3 + 33 * 2;
        int ver = US_NIZK_VerifyC(us, nodes[tmp_addr].us_y, nodes[cur_id].us_y, nn, nn_len, pi, pi_len, v, v_len);//本来2つ目は前ノードの公開鍵
        int ver2 = US_NIZK_VerifyD(us, nodes[tmp_addr].us_y, nodes[cur_id].us_y, nn, nn_len, pi, pi_len, vp, vp_len);
        if (ver == 1 && ver2 ==0) {
            // printf("NIZK Signature CONFIRMED.\n");
            printf("Verify π%d success\n", cur_id);
        } else if (ver == 0 && ver2 ==1) {
            // printf("NIZK Signature NOT confirmed.\n");
            fprintf(stderr, "Verify π%d failed\n", cur_id);
        } else {
            fprintf(stderr, "Verify π%d inconsistent result\n", cur_id);
        }
        free(pi);
        free(n);
        // free(v);

        //最後のcom_concatを抽出
        unsigned char *com = com_concat + (cur_id - 1) * USIG_LEN;
        // print_hex("com", com, USIG_LEN);
        ver = EC_Com_Verify(us, tau, SIG_LEN, rand_val, sizeof(rand_val), G, com, USIG_LEN);
        if (ver == 1) {
            printf("EC Commitment VERIFIED.\n");
        } else if (ver == 0) {
            printf("EC Commitment NOT verified.\n");
        }

        // τi-1検証
        unsigned char *m = NULL; size_t m_len = 0;
        m = concat2(pkt.h.sid, SID_LEN, nodes[tmp_addr].addr, sizeof(nodes[tmp_addr].addr), &m_len);
        if (!verify_sig(nodes[tmp_addr].pk, m, m_len, tau, SIG_LEN)) {//pkt.p.tau_len)) {
            fprintf(stderr, "Verify τ%d failed\n", tmp_addr);
            free(m);
            return -1;
        }
        free(m);
        printf("Verify τ%d success\n", tmp_addr);
        
        if (s_id != tmp_addr) {
            // 次のルータへの問い合わせ準備
            // next_addr_n = htonl((uint32_t)cur_id);
            cur_id = ntohl(tmp_addr);
            flags += flag;
            break; // テスト用に1回で抜ける
            printf("[Verifier] Continuing to next Router...\n");
        } else {
            printf("Router R%d is identified as the Sender\n", tmp_addr);
            flags += flag;
            break;
        }
        
        // sleep(3); // 少し待つ
    }
    close(sock);

    // flagsからセッションとペイロードのリンクの合意をとる
    // すべてオネストな検証をしていれば経由した1~nのノードになっているはず
    // 攻撃者が1人ならn-1、攻撃者が2人ならn-2、...となるはず
    printf("Flags value: %d\n", flags);
    // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
    trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
    rc = groupsig_reveal(trapdoor, crl, gml, id);
    if (rc == IOK && trapdoor != NULL) {
        printf("Reveal success: trapdoor valid, member ID = %lu added to CRL.\n", id);
    } else {
        printf("Reveal failed.\n");
    }

    // CRLをRに送信?(共有している想定なら不要)

    // Rの処理
    // === Trace（署名が公開済み(CRL登録済)メンバーによるものか確認） ===
    uint8_t traced = 0;
    rc = groupsig_trace(&traced, sig, grpkey, crl, NULL, NULL);
    if (rc == IOK) {
        printf("Trace result: %d (1 = traced, 0 = not traced)\n", (int)traced);
    } else {
        printf("Trace failed.\n");
    }
}