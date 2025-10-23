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

int main(void) {
    RAND_load_file("/dev/urandom", 32);

    // === 初期化 ===
    Node nodes[NODES];
    for (int i = 0; i < NODES; i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    unsigned char tau[SIG_LEN];
    size_t tau_len = SIG_LEN;
    size_t m_len;
    unsigned char *m = NULL;

    printf("======= 経路設定フェーズ =======");
    printf("\n===============================往路=================================\n");
    printf("=== Node S(R0) ===\n");


    Packet pkt;
    // k_C 公開鍵取り出し & SID=H(k_C)
    unsigned char kC_pub[PUB_LEN];
    int idx = 0;
    Node *me = &nodes[idx];
    get_raw_pub(me->dh_sk, kC_pub);
    // print_hex("kC_pub", kC_pub, PUB_LEN);

    // --- グループ署名生成 ---
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);

    message_t *gsm = message_from_bytes(kC_pub, PUB_LEN);
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
    groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);
    // char *strsig = groupsig_signature_to_string(sig);
    // printf("sig: %s\n", strsig);
    // free(strsig);

    // // --- 署名をバイナリに変換 ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = sizeof(sig);
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    printf("Exported signature length: %u bytes\n", sig_size);
    free(sig);


    // unsigned char* にキャスト（byte_t は typedef unsigned char）
    unsigned char *uc_sig = (unsigned char *)malloc(sig_size);
    memcpy(uc_sig, sig_bytes, sig_size);
    // print_hex("Group signature σ", uc_sig, sig_size);

    // --- SID 生成 ---
    size_t sid_len;
    unsigned char *sid = concat2(kC_pub, PUB_LEN, uc_sig, sig_size, &sid_len);
    hash_sid_from_pub(sid, pkt.h.sid);
    print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
    RAND_bytes(pkt.h.cid, CID_LEN);
    pkt.h.status = SETUP_REQ;

    // --- 各ノードの共有鍵 k_i を計算して c_i を生成 ---
    unsigned char sharenode[SEC_LEN];
    for (int i = 1; i < NODES; i++) {
        derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
        memcpy(me->k[i], sharenode, KEY_LEN);
        // print_hex("Shared secret k_i", me->k[i], KEY_LEN);

        unsigned char *prehop = nodes[i - 1].addr;
        unsigned char *nexthop = (i == NODES - 1) ? nodes[i].addr : nodes[i + 1].addr;
        unsigned char *nnexthop = (i >= NODES - 2) ? nodes[i].addr : nodes[i + 2].addr;

        size_t p_len;
        unsigned char *p = concat2(prehop, 4, nexthop, 4, &p_len);
        size_t ap_len;
        unsigned char *ap = concat2(p, p_len, nnexthop, 4, &ap_len);

        unsigned char ci[SEG_LEN];
        unsigned char iv[IV_LEN], tag[TAG_LEN];
        aead_encrypt(me->k[i], ap, ap_len, pkt.h.sid, iv, ci, tag);

        size_t offset = (size_t)((i - 1) % (ROUTERS + 1)) * (SEG_LEN + TAG_LEN + IV_LEN);
        memcpy(pkt.h.seg_concat + offset, ci, SEG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN, tag, TAG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN + TAG_LEN, iv, IV_LEN);
        free(p); free(ap);
    }

    // --- τ0 署名 ---
    m = concat2(pkt.h.sid, SID_LEN, nodes[idx].addr, sizeof(nodes[idx].addr), &m_len);
    sign_data(nodes[idx].sk, m, m_len, tau, &tau_len);
    free(m);
    memcpy(pkt.p.tau, tau, tau_len);
    memcpy(pkt.p.peer_pub, kC_pub, PUB_LEN);
    pkt.p.sig_len = sig_size;
    memcpy(pkt.p.sig_bytes, sig_bytes, sig_size);

    // 状態保存
    unsigned char precid[CID_LEN];
    memset(precid, 0, CID_LEN);
    state_set(&nodes[idx], pkt.h.sid, precid, pkt.h.cid, -1, nodes[idx + 1].id,
              nodes[idx + 2].id, pkt.p.tau, SIG_LEN);

    pkt.h.idx = 1;

    // === パケット構築 ===
    unsigned char frame[MAX_PKT];
    memset(frame, 0, sizeof(frame));
    size_t l2l3_len = write_l2l3_min(frame, sizeof(frame));
    size_t wire_len = build_overlay_setup_req(frame, sizeof(frame), &pkt);
    size_t total_len = l2l3_len + wire_len;
    // print_hex("Final frame before padding", frame, total_len);
    if (total_len < MAX_PKT) {
        memset(frame + total_len, 0, MAX_PKT - total_len);
    }
    total_len = MAX_PKT; // 送信サイズを固定化
    // printf("S sending SETUP_REQ (%zu bytes)\n", wire_len);
    // print_hex("Final frame", frame, MAX_PKT);

    // === ソケット送信 ===
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);

    if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        return 1;
    }

    uint32_t len_n = htonl(total_len);
    send(sock, &len_n, sizeof(len_n), 0);
    send(sock, frame, total_len, 0);
    printf("S sent SETUP_REQ (%zu bytes)\n", total_len);

    close(sock);

    // 後処理
    groupsig_signature_free(sig);
    groupsig_mem_key_free(memkey);
    groupsig_grp_key_free(grpkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);

    free(sig_bytes);
    free(sid);
    return 0;
}
