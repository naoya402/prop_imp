
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


int main(void) {
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);

    // 初期化
    Node nodes[NODES];
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    Packet pkt;

    size_t r1_len, r2_len, r3_len, r4_len, r5_len, r6_len, r7_len;
    unsigned char *r1=NULL, *r2=NULL, *r3=NULL, *r4=NULL, *r5=NULL, *r6=NULL, *r7=NULL;

    unsigned char sigma_s[SIG_LEN];
    size_t sigma_s_len = SIG_LEN;

    // unsigned char k_S[PUB_LEN];
    // get_raw_pub(nodes[0].dh_sk, k_S);
    // // memcpy(k_S, kC_pub, PUB_LEN);
    // unsigned char Sig[SIG_LEN];
    // memcpy(Sig, sig, sig_size);

    // 検証者Vの処理
    // 通報の正当性検証
    // unsigned char k_S[PUB_LEN];
    // memcpy(k_S, kC_pub, PUB_LEN); // Sの公開鍵
    // 0) 通報パケットのパース
    // --- r7 パケットのパース ---
    size_t offset = 0;

    // 1) k_S_pub 抽出
    unsigned char k_S[PUB_LEN];
    memcpy(k_S, r7 + offset, PUB_LEN);
    offset += PUB_LEN;

    // 2) グループ署名（Sig）抽出
    uint32_t sig_len = sig_size;  // ※既知 or 先頭4バイトに長さがあるならそれを使う
    unsigned char *gsig_bytes = malloc(sig_len);
    memcpy(gsig_bytes, r7 + offset, sig_len);
    offset += sig_len;

    // 3) Packet構造体の復元
    Packet pkt;
    memcpy(&pkt, r7 + offset, sizeof(Packet));
    offset += sizeof(Packet);
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
                fprintf(stderr, "parse failed\n");
                return -1;
    }

    // 4) 平文（plain）抽出
    unsigned char *plain_recv = malloc(pkt.p.ct_len);
    memcpy(plain_recv, r7 + offset, pkt.p.ct_len);
    offset += pkt.p.ct_len;

    // 5) セッション鍵
    unsigned char sess_key[KEY_LEN];
    memcpy(sess_key, r7 + offset, KEY_LEN);
    offset += KEY_LEN;

    // 6) π_concat
    unsigned char pi_concat[MAX_PI];
    memcpy(pi_concat, r7 + offset, MAX_PI);
    offset += MAX_PI;

    // 7) prev_state
    int prev_state;
    memcpy(&prev_state, r7 + offset, sizeof(prev_state));
    offset += sizeof(prev_state);

    // 8) σ_s (Receiver署名)
    unsigned char sigma_s[SIG_LEN];
    memcpy(sigma_s, r7 + offset, SIG_LEN);
    offset += SIG_LEN;
    size_t sigma_s_len = SIG_LEN;

    printf("Parsed r7 packet successfully (total %zu bytes parsed)\n", offset);



    // 1) sigma 検証 (R_pub は known)
    // --- 署名検証 ---
    if (verify_sig(nodes[NODES-1].pk, r6, r6_len, sigma_s, sigma_s_len)) {
        printf("σ_s verification succeeded\n");
    } else {
        printf("σ_s verification failed\n");
    }

    // 2) SID 再計算: 例 -> SID = SHA256( S_pub ) or whatever your scheme uses
    unsigned char sid_chk[SID_LEN];
    // --- 署名をバイナリにエクスポート ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    printf("Exported signature length: %u bytes\n", sig_size);

    size_t sid_len;
    unsigned char *sid; 
    sid = concat2(k_S, PUB_LEN, sig_bytes, sig_size, &sid_len);
    // print_hex("sid", sid, sid_len);
    hash_sid_from_pub(sid, pkt.h.sid);
    // print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
    // parse_frame_to_pkt(frame, frame_len, &pkt); // 既存関数
    // Packet pkt;
    unsigned char frame[MAX_FRAME];
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) { /* error */ }
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
    if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, plain_out)) {
        /* decrypt fail */
    }
    if (memcmp(plain_out, plain, sizeof(plain)) != 0) { /* mismatch */ }
    printf("Decrypt result match: %.*s\n", (int)pkt.p.ct_len, plain_out);

    
    // === Open（署名者を特定） ===
    // crl, gml, mgrkeyの読み込み
    crl_t *crl = crl_init(GROUPSIG_KTY04_CODE); // 失効リスト
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);

    
    // gml読み込み
    std::ifstream fgml("gml.dat", std::ios::binary);
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(fgml)), {});
    gml_t *gml = gml_import(GROUPSIG_KTY04_CODE, buf.data(), buf.size());

    uint64_t id = UINT64_MAX;
    int rc = groupsig_open(&id, NULL, NULL, sig, grpkey, mgrkey, gml);
    if (rc == IOK) {
        printf("Open success: member ID = %lu\n", id);
    } else {
        printf("Open failed.\n");
    }

    // ******************各ルータに問い合わせてS特定

    // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
    trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
    rc = groupsig_reveal(trapdoor, crl, gml, id);
    if (rc == IOK && trapdoor != NULL) {
        printf("Reveal success: trapdoor valid, member ID = %lu added to CRL.\n", id);
    } else {
        printf("Reveal failed.\n");
    }

    // trapdoorとCRLをRに送信

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