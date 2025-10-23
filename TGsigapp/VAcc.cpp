
#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include <time.h>
#include <unistd.h>

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


int main(void) {
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    // 初期化
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
    uint32_t len_n;
    recv(client, &len_n, sizeof(len_n), 0);
    uint32_t len = ntohl(len_n);

    unsigned char r9[len];
    recv(client, r9, len, MSG_WAITALL);
    printf("[Verifier] Received r9 (%u bytes)\n", len);
    // print_hex("r9", r9, len);    

    // 通報パケットのパース
    size_t offset = 0;

    // 1) k_S_pub 抽出
    unsigned char k_S[PUB_LEN];
    memcpy(k_S, r9 + offset, PUB_LEN); offset += PUB_LEN;
    // print_hex("k_S", k_S, PUB_LEN);

    // 2) グループ署名（Sig）抽出
    size_t sig_len;
    memcpy(&sig_len, r9 + offset, 4); offset += 4;
    // printf("sig_len: %zu\n", sig_len);
    unsigned char gsig_bytes[sig_len];
    memcpy(gsig_bytes, r9 + offset, sig_len); offset += sig_len;
    // print_hex("gsig_bytes", gsig_bytes, sig_len);
    groupsig_signature_t *sig = groupsig_signature_import(GROUPSIG_KTY04_CODE, gsig_bytes, sig_len);
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

    // 4) 平文（plain）抽出
    unsigned char plain_recv[pkt.p.ct_len];
    memcpy(plain_recv, r9 + offset, pkt.p.ct_len); offset += pkt.p.ct_len;
    // printf("plain_recv: %.*s\n", (int)pkt.p.ct_len, plain_recv);

    // 5) セッション鍵
    unsigned char sess_key[KEY_LEN];
    memcpy(sess_key, r9 + offset, KEY_LEN); offset += KEY_LEN;
    // print_hex("sess_key", sess_key, KEY_LEN);

    // 6) π_concat
    unsigned char pi_concat[MAX_PI];
    memcpy(pi_concat, r9 + offset, MAX_PI); offset += MAX_PI;
    // print_hex("pi_concat", pi_concat, MAX_PI);

    // 7) prev_state
    int prev_state;
    memcpy(&prev_state, r9 + offset, sizeof(prev_state)); offset += sizeof(prev_state);
    // printf("prev_state: %d\n", prev_state);

    // 8) σ_R (Receiver署名)
    unsigned char sigma_r[SIG_LEN];
    memcpy(sigma_r, r9 + offset, SIG_LEN); offset += SIG_LEN;
    // size_t sigma_r_len = SIG_LEN;
    // print_hex("sigma_r", sigma_r, SIG_LEN);

    // printf("Parsed r9 packet successfully (total %zu bytes parsed)\n", offset);

    // 通報の正当性検証
    // 1) sigma 検証 (R_pub は known)
    // --- 署名対象データ (σ_r を除く部分) ---
    size_t r_len = len - SIG_LEN;  // r9 全体から σ_r を除いた長さ
    unsigned char *r = (unsigned char *)malloc(r_len);
    memcpy(r, r9, r_len);
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
    message_t *kSb = message_from_bytes(k_S, PUB_LEN);
    groupsig_verify(&val, sig, kSb, grpkey);
    printf("TGsig verification: %s\n", val ? "valid" : "invalid");

    // 4) ペイロード復号
    // ここでは pkt.p.iv, pkt.p.ct, pkt.p.tag を利用する
    unsigned char plain_out[MAX_PTXT];
    if (!aead_decrypt(sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain_out)) {
        /* decrypt fail */
    }
    // printf("plain_out: %.*s\n", (int)pkt.p.ct_len, plain_out);
    if (memcmp(plain_out, plain_recv, sizeof(plain_recv)) != 0) { /* mismatch */ }
    printf("Decrypt result match: %.*s\n", (int)pkt.p.ct_len, plain_out);
    
    // 5) コントラクト検証
    int blocked = apply_policy_contract((const char *)plain_recv);
    if (!blocked) {// 以降の処理は行わない
    } 
    printf("Policy contract False.\n");

    // === Open（署名者を特定） ===
    // crl, gml, mgrkeyの読み込み
    crl_t *crl = crl_init(GROUPSIG_KTY04_CODE); // 失効リスト
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);

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

    uint64_t id = UINT64_MAX;
    int rc = groupsig_open(&id, NULL, NULL, sig, grpkey, mgrkey, gml);
    if (rc == IOK) {
        printf("Open success: member ID = %lu\n", id);
    } else {
        printf("Open failed.\n");
    }
    
    // ルータから得たidリストと比較してSを特定
    const char *signer = router_addresses[id]; // 仮にidをインデックスとしてSを特定
    // gml_entry_t *entry = gml_get(gml, id);
    // if (!entry) {
    //     fprintf(stderr, "No entry found for ID %lu\n", id);
    // }
    // char *entry_str = gml_entry_to_string(entry);
    // printf("=== GML Entry ID %lu ===\n%s\n", id, entry_str);
    // free(entry_str);

    // 各ノードに問い合わせてS特定
    // idがそのままSのIDとする
    uint64_t s_id = id;

    // 送信パケットの構築
    // ペイロード部の連結
    size_t pay_len = IV_LEN + 2 + pkt.p.ct_len + TAG_LEN;
    unsigned char *pay_buf1; size_t pay_buf1_len;
    unsigned char *pay_buf2; size_t pay_buf2_len;
    unsigned char *pay_buf3; size_t pay_buf3_len;
    uint16_t ctlen_n = htons((uint16_t)pkt.p.ct_len);
    pay_buf1 = concat2(pkt.p.iv, IV_LEN, (unsigned char*)&ctlen_n, 2, &pay_buf1_len);
    pay_buf2 = concat2(pay_buf1, pay_buf1_len, pkt.p.ct, pkt.p.ct_len, &pay_buf2_len);
    pay_buf3 = concat2(pay_buf2, pay_buf2_len, pkt.p.tag, TAG_LEN, &pay_buf3_len);
    // SID(32B) || Payload(41B) || next_addr(4B)|| ACSEG((ROUTERS)*32B)
    unsigned char *ac_plain1; size_t ac_plain1_len;
    unsigned char *ac_plain2; size_t ac_plain2_len;
    unsigned char *ac_plain3; size_t ac_plain3_len;

    uint32_t next_addr_n = htonl((uint32_t)pkt.h.idx);//次のルータアドレスを現在のインデックスに指定 本来はstateから取得
    ac_plain1 = concat2(pkt.h.sid, SID_LEN, pay_buf3, pay_len, &ac_plain1_len);
    // print_hex("AC_SEG: ", pkt.h.acseg_concat, (pkt.h.idx - 1) * ACSEG_LEN);
    // print_hex("AC_PLAIN: ", ac_plain3, ac_plain3_len);
    
    // // Sになるまで問い合わせループ
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    uint32_t cur_id = prev_state; // 最後に接続したルータのIDから開始
    int flags = 0;
    while (1) {
        // ルータに問い合わせてSを特定
        ac_plain2 = concat2(ac_plain1, ac_plain1_len, (unsigned char*)&next_addr_n, 4, &ac_plain2_len);
        ac_plain3 = concat2(ac_plain2, ac_plain2_len, pkt.h.acseg_concat, (pkt.h.idx - 1) * ACSEG_LEN, &ac_plain3_len);
        // === ソケット送信 ===
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(9010);
        inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);

        if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            return 1;
        }

        uint32_t resp_len_n = htonl(ac_plain3_len);
        send(sock, &resp_len_n, sizeof(resp_len_n), 0);
        send(sock, ac_plain3, ac_plain3_len, 0);
        printf("[Verifier] Sent INQ to R%d\n", 1);//cur_id);


        //問い合わせの応答受信
        uint32_t reinq_len_n;
        recv(sock, &reinq_len_n, sizeof(reinq_len_n), 0);
        uint32_t reinq_len = ntohl(reinq_len_n);

        unsigned char reinq[reinq_len];
        recv(sock, reinq, reinq_len, MSG_WAITALL);
        printf("[Verifier] Received REINQ (%u bytes) from R%d\n", reinq_len, 1);//cur_id);
        // print_hex("reinq", reinq, reinq_len);

        // ノードからの応答パケットのパース
        size_t offset = 0;
        int tmp_addr = 0; // 本来前ホップアドレス(今回はID)
        int flag = 0; // 各ノードのアカセグ検証結果フラグ
        unsigned char rand_val[4];
        unsigned char tau[SIG_LEN];
        memcpy(&tmp_addr, reinq + offset, sizeof(tmp_addr)); offset += sizeof(tmp_addr);
        // printf("[Verifier] Received next Router ID: %d\n", tmp_addr);
        memcpy(tau, reinq + offset, SIG_LEN); offset += SIG_LEN;
        // print_hex("[Verifier] Received tau: ", tau, SIG_LEN);
        memcpy(rand_val, reinq + offset, sizeof(rand_val)); offset += sizeof(rand_val);
        // print_hex("[Verifier] Received rand_val: ", rand_val, sizeof(rand_val));
        memcpy(&flag, reinq + offset, 2); offset += 2;
        // printf("Received flag: %d\n", flag);

        // π検証  通報のpi_concatからπiを抽出して検証
        // print_hex("pi_concat", pi_concat, MAX_PI);
        size_t pioffset = (tmp_addr) * SIG_LEN;
        if (pioffset + SIG_LEN > MAX_PI) {
            fprintf(stderr,"pi_concat out of range\n");
            return -1;
        }
        unsigned char *pi_vrf = pi_concat + pioffset;
        // print_hex("pi_vrf", pi_vrf, SIG_LEN);
        size_t n_len;
        unsigned char *n = concat2(tau, SIG_LEN, rand_val, sizeof(rand_val), &n_len);
        if (!verify_sig(nodes[tmp_addr].pk, n, n_len, pi_vrf, SIG_LEN)) {
            free(n); 
            fprintf(stderr,"Verify π%d failed\n", tmp_addr + 1); 
            return -1;
        }
        free(n);
        printf("Verify π%d success \n", tmp_addr + 1);
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
            next_addr_n = htonl((uint32_t)cur_id);
            cur_id = ntohl(tmp_addr);
            printf("[Verifier] Continuing to next Router...\n");
            flags += flag;
        } else {
            // // τi-1検証
            // unsigned char *m = NULL; size_t m_len = 0;
            // m = concat2(pkt.h.sid, SID_LEN, nodes[tmp_addr].addr, sizeof(nodes[tmp_addr].addr), &m_len);
            // if (!verify_sig(nodes[tmp_addr].pk, m, m_len, tau, SIG_LEN)) {//pkt.p.tau_len)) {
            //     fprintf(stderr, "Verify τ%d failed\n", tmp_addr);
            //     free(m);
            //     return -1;
            // }
            // printf("Verify τ%d success\n", tmp_addr);
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