#include "func.h"

// typedef enum { SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;



EVP_MD_CTX *mdctx1 = NULL;// 署名用
EVP_MD_CTX *mdctx2 = NULL;// 検証用
const char *router_addresses[] = {
    "192.168.10.0",
    "192.168.10.1",
    "192.168.10.2",
    "192.168.10.3",
    "192.168.10.4",
    "192.168.10.5",
    "192.168.10.6",
    "192.168.10.7",
    "192.168.10.8"
};
    

// ポリシー
const char *policy[] = {"attack", "leak", "bomb", "hello"};
const int POLICY_COUNT = sizeof(policy) / sizeof(policy[0]);

void die(const char *msg) {
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(EXIT_FAILURE);
}

void die_ossl(const char *msg) {
    fprintf(stderr, "OpenSSL ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

EVP_PKEY* gen_x25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");
    EVP_PKEY *p = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("keygen_init");
    if (EVP_PKEY_keygen(ctx, &p) <= 0) die("keygen");
    EVP_PKEY_CTX_free(ctx);
    return p;
}

EVP_PKEY *load_ed25519_seckey_pem(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen read failed");
    EVP_PKEY *p = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!p) die_ossl("PEM_read_PrivateKey");
    return p;
}

EVP_PKEY *load_ed25519_pubkey_pem(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen read failed");
    EVP_PKEY *p = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!p) die_ossl("PEM_read_PUBKEY");
   //  print_ed25519_pubkey(p);
    return p;
}

// DH秘密鍵から公開鍵を取得
void get_raw_pub(EVP_PKEY *pkey, unsigned char pub[PUB_LEN]) {
    size_t len = PUB_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0 || len != PUB_LEN) die("get_raw_public_key");
}

// 公開鍵のインポート
EVP_PKEY* import_x25519_pub(const unsigned char *pub) {
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, PUB_LEN);
    if (!p) die("new_raw_public_key");
    return p;
}

// X25519 共有秘密の導出
void derive_shared(const EVP_PKEY *my_sk, const EVP_PKEY *peer_pub, unsigned char sec[SEC_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)my_sk, NULL);
    if (!ctx) die("derive ctx");
    if (EVP_PKEY_derive_init(ctx) <= 0) die("derive_init");
    if (EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY*)peer_pub) <= 0) die("set_peer");
    size_t outlen = SEC_LEN;
    if (EVP_PKEY_derive(ctx, sec, &outlen) <= 0 || outlen != SEC_LEN) die("derive");
    EVP_PKEY_CTX_free(ctx);
}

EVP_PKEY* gen_ed25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) die_ossl("EVP_PKEY_CTX_new_id");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die_ossl("EVP_PKEY_keygen_init");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) die_ossl("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY* extract_public_only(const EVP_PKEY *priv) {
    unsigned char pub[PUB_LEN];
    size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(priv, pub, &publen) <= 0)
        die_ossl("EVP_PKEY_get_raw_public_key");
    EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, publen);
    if (!pubkey) die_ossl("EVP_PKEY_new_raw_public_key");
    return pubkey;
}

void hash_sid_from_pub(const unsigned char *pub, unsigned char sid[SID_LEN]) {
    SHA256(pub, PUB_LEN, sid);
}

unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen) {
    *outlen = alen + blen;
    unsigned char *buf = (unsigned char*)malloc(*outlen);
    if (!buf) die("malloc failed");
    memcpy(buf, a, alen);
    memcpy(buf + alen, b, blen);
    return buf;
}

// Ed25519 署名・検証
// 初期化処理（
void init_crypto(EVP_PKEY *sk, EVP_PKEY *pk) {
    mdctx1 = EVP_MD_CTX_new();
    if (!mdctx1) die_ossl("EVP_MD_CTX_new sign");
    if (EVP_DigestSignInit(mdctx1, NULL, NULL, NULL, sk) <= 0)
        die_ossl("EVP_DigestSignInit");

    mdctx2 = EVP_MD_CTX_new();
    if (!mdctx2) die_ossl("EVP_MD_CTX_new verify");
    if (EVP_DigestVerifyInit(mdctx2, NULL, NULL, NULL, pk) <= 0)
        die_ossl("EVP_DigestVerifyInit");
}

// AES-GCM暗号化
void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]) {
    RAND_bytes(iv, IV_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("cipher ctx");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("enc_init1");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) die("set_ivlen");
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) die("enc_init2");
    int len;
    if (EVP_EncryptUpdate(ctx, NULL, &len, sid, SID_LEN) != 1) die("aad");
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) die("enc_upd");
    int ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) die("enc_fin");
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) die("get_tag");
    EVP_CIPHER_CTX_free(ctx);
}

int aead_decrypt(const unsigned char key[KEY_LEN], const unsigned char *ct, size_t ct_len, const unsigned char sid[SID_LEN], const unsigned char iv[IV_LEN], const unsigned char tag[TAG_LEN], unsigned char *pt_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("cipher ctx");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("dec_init1");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) die("set_ivlen");
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) die("dec_init2");
    int len, ptlen;
    if (EVP_DecryptUpdate(ctx, NULL, &len, sid, SID_LEN) != 1) die("aad");
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) die("dec_upd");
    ptlen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) die("set_tag");
    int ok = EVP_DecryptFinal_ex(ctx, pt_out + ptlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1; // 1=auth OK
}

// Ed25519 署名・検証
void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) <= 0)
        die_ossl("EVP_DigestSignInit");
    if (EVP_DigestSign(mdctx, sig, siglen, data, datalen) <= 0)
        die_ossl("EVP_DigestSign");
    EVP_MD_CTX_free(mdctx);
}

int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk) <= 0)
        die_ossl("EVP_DigestVerifyInit");
    int ok = EVP_DigestVerify(mdctx, sig, siglen, data, datalen);
    EVP_MD_CTX_free(mdctx);
    return ok == 1;
}

// 自身のノード初期化
void node_init(Node *node, int id, const char *addr) {
    memset(node, 0, sizeof(Node));
    node->id = id;
   //  node->sk = gen_ed25519_keypair();
   //  node->pk = extract_public_only(node->sk);
   //  save_ed25519_seckey_pem(node->sk, "ed25519_sec.pem");
   //  save_ed25519_pubkey_pem(node->pk, "ed25519_pub.pem");
    node->sk = load_ed25519_seckey_pem("ed25519_sec.pem"); // 既存秘密鍵の読み込み
    node->pk = load_ed25519_pubkey_pem("ed25519_pub.pem"); // 既存公開鍵の読み込み
    init_crypto(node->sk, node->pk);// 今はどのノードの鍵も一緒なので自身の鍵で初期化しておく


    node->dh_sk = load_ed25519_seckey_pem("dh_sec.pem");//gen_x25519_keypair();//ここでファイル読み込みしたい
    unsigned char pub[PUB_LEN];
    get_raw_pub(node->dh_sk, pub);
    node->dh_pk = import_x25519_pub(pub);
    // RAND_bytes(node->addr, sizeof(node->addr));
   //  // IPv4アドレスの設定
   //  inet_pton(AF_INET, addr, &ipv4_addr);
   //  printf("IPv4 address: %s\n", inet_ntoa(ipv4_addr));
    // nodeのaddrにaddrをコピー
   //  rte_memcpy(node->addr, addr, sizeof(node->addr));
   if (inet_pton(AF_INET, addr, node->addr) != 1) {
        die("inet_pton failed in prev_node_init");
    }
    RAND_bytes(node->rand_val, sizeof(node->rand_val));
}

void node_free(Node *n) {
    if (n->dh_sk) EVP_PKEY_free(n->dh_sk);
    if (n->sk) EVP_PKEY_free(n->sk);
    if (n->pk) EVP_PKEY_free(n->pk);
}

// ステート操作
void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char precid[CID_LEN], unsigned char nexcid[CID_LEN], unsigned char prev_addr, int next_addr, int nnext_addr, const unsigned char *tau, size_t tau_len) {
    for (int i=0;i<MAX_STATE;i++) {
        if (!n->state[i].used) {
            n->state[i].used = 1;
            memcpy(n->state[i].sid, sid, SID_LEN);
            memcpy(n->state[i].precid, precid, CID_LEN);
            memcpy(n->state[i].nexcid, nexcid, CID_LEN);
            n->state[i].prev_addr = prev_addr;
            n->state[i].next_addr = next_addr;
            n->state[i].nnext_addr = nnext_addr;
            if (tau && tau_len > 0) {
                memcpy(n->state[i].tau, tau, tau_len);
                n->state[i].tau_len = tau_len;
            }
            return;
        }
    }
    die("state full");
}

int state_get_next(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].next_addr;
    }
    return -1;
}

int state_get_prev(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].prev_addr;
    }
    return -1;
}

const unsigned char* state_get_tau(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            return n->state[i].tau;
    }
    return NULL;
}


//========= オーバーレイ領域ヘッダ & ペイロード=========
size_t overlay_header_footprint(void) { return SID_LEN + CID_LEN + 1 + 1 + 4; }//固定へッダ長

// L2/L3 ダミーを埋めて最小 IPv4 ヘッダ(IHL = 5)作成
size_t write_l2l3_min(unsigned char *buf, size_t buf_cap) {
    if (buf_cap < ETH_LEN + sizeof(IPv4Hdr)) die("buf too small for L2/L3");
    EthHdr *eth = (EthHdr*)buf;
    memset(eth->dst, 0xff, 6);
    memset(eth->src, 0x11, 6);
    eth->ethertype = htons(0x0800);
    IPv4Hdr *ip = (IPv4Hdr*)(buf + ETH_LEN);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = (4<<4) | 5; // ver=4, IHL=5 => 20B
    ip->ttl = 64;
    ip->proto = 0xFD; // experimental
    return ETH_LEN + sizeof(IPv4Hdr);
}

// ======== オーバーレイのビルド/パース ========
size_t ipv4_header_len_bytes(const IPv4Hdr *ip) {
    return 4 * (ip->ver_ihl & 0x0F); // IHL * 4
}

size_t l3_overlay_offset(const unsigned char *l2) {
    const EthHdr *eth = (const EthHdr*)l2;
    (void)eth; // VLAN 無し前提。VLAN 対応は実運用で追加。
    const IPv4Hdr *ip = (const IPv4Hdr*)(l2 + ETH_LEN);
    return ETH_LEN + ipv4_header_len_bytes(ip); // 14 + IHL*4
}

// SETUP_REQ を 34B(=L3末) から書く
size_t build_overlay_setup_req(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    size_t need = off + overlay_header_footprint() + (pkt->h.idx - 1) * SIG_LEN + SIG_LEN + PUB_LEN;
    if (cap < need) die("cap too small (setup req)");
    unsigned char *p = l2 + off; //現在の位置 ＋ L2L3オフセット
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, pkt->h.cid, CID_LEN); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // print_hex("pkt.h.sid", pkt->h.sid, SID_LEN);

    // seg_concatを乗せる
    memcpy(p, pkt->h.seg_concat, MAX_SEG_CON); p += MAX_SEG_CON; // segリストは固定長
    // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
    memcpy(p, pkt->h.pi_concat, (pkt->h.idx - 1) * SIG_LEN); p += (pkt->h.idx - 1) * SIG_LEN; // πリストは固定長
    // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, (pkt->h.idx - 1) * SIG_LEN);

    // ぺイロード
    memcpy(p, pkt->p.tau, SIG_LEN); p += SIG_LEN; //固定長で送る
    // print_hex("pkt.p.tau", pkt->p.tau, SIG_LEN);
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN;
    // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
    // print_hex("Built SETUP_REQ", l2 + off, (size_t)(p - l2 - off));
    // 署名長もpに乗せる
    uint32_t sig_len_n = htonl(pkt->p.sig_len);
    memcpy(p, &sig_len_n, sizeof(sig_len_n));
    // print_hex("pkt.p.sig_len", p, sizeof(sig_len_n));
    p += sizeof(sig_len_n);
    memcpy(p, pkt->p.sig_bytes, pkt->p.sig_len);p += pkt->p.sig_len;

    return (size_t)(p - l2 - off); // 書き終わったバイト位置
}

// SETUP_RESP を書く（DST_S/πリスト付き）
size_t build_overlay_setup_resp(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    size_t need = off + overlay_header_footprint() + MAX_PI + SIG_LEN + 4 + PUB_LEN;
    if (cap < need) die("cap too small (setup resp)");
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, pkt->h.cid, CID_LEN); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // printf("R%d\n", pkt->h.idx);
    memcpy(p, pkt->h.pi_concat, MAX_PI); p += MAX_PI; //固定長で送る
    memcpy(p, pkt->h.rho, SIG_LEN * 2); p += SIG_LEN * 2; //固定長で送る
    // print_hex("rho", pkt->h.rho, SIG_LEN*2);
    // ペイロード
    memcpy(p, pkt->p.rand_val, sizeof(pkt->p.rand_val)); p += sizeof(pkt->p.rand_val); // 4
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN; //32

    return (size_t)(p - l2 - off);
}

// DATA_TRANS を書く
size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    uint16_t ctlen = (uint16_t)pkt->p.ct_len;
    size_t need = off + overlay_header_footprint() + IV_LEN + 2 + ctlen + TAG_LEN;
    if (cap < need) die("cap too small (data trans)");
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, &pkt->h.cid, 1); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // ぺイロード
    memcpy(p, pkt->p.iv, IV_LEN); p += IV_LEN;
    uint16_t n = htons(ctlen); memcpy(p, &n, 2); p += 2;
    memcpy(p, pkt->p.ct, ctlen); p += ctlen;
    memcpy(p, pkt->p.tag, TAG_LEN); p += TAG_LEN;
    return (size_t)(p - l2 - off);
}

// フレームからパケットをパース
int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt) {

    // L2/L3を読み飛ばす
    size_t l3end = 34;//read_l2l3_min(frame, frame_len);
    if (l3end == 0) return -1;
    const unsigned char *buf = frame + l3end;
    const unsigned char *p = buf;
    size_t len = frame_len - l3end;
    if (len < SID_LEN + 2 + 1 + 1) return -1; // sid + status + dest
    
    //固定ヘッダ
    memcpy(pkt->h.sid, p, SID_LEN); p += SID_LEN;
    // print_hex("pkt.h.sid", pkt->h.sid, SID_LEN);
    memcpy(pkt->h.cid, p, CID_LEN); p += CID_LEN;
    pkt->h.status = *p++;
    pkt->h.idx = *p++;
    
    if (pkt->h.status == SETUP_REQ) {
        // seg_listをパース
        if (p + MAX_SEG_CON > buf + len) return -1;
        memcpy(pkt->h.seg_concat, p, MAX_SEG_CON); // segリストは固定長で受け取る
        // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
        p += MAX_SEG_CON;
        //π_list
        if (p + (pkt->h.idx - 1) * SIG_LEN > buf + len) return -1;
        memcpy(pkt->h.pi_concat, p, (pkt->h.idx - 1) * SIG_LEN); // πリストはidxによる可変長で受け取る
        // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, (pkt->h.idx - 1) * SIG_LEN);
        p += (pkt->h.idx - 1) * SIG_LEN;

        //  τ + peer_pub
        if (p + SIG_LEN > buf + len) return -1;
        memcpy(pkt->p.tau, p, SIG_LEN); p += SIG_LEN;
        // print_hex("pkt.p.tau", pkt->p.tau, SIG_LEN);
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
        // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
        // グループ署名
        uint32_t sig_len_n;
        memcpy(&sig_len_n, p, sizeof(sig_len_n));
        pkt->p.sig_len = ntohl(sig_len_n);
        p += sizeof(sig_len_n);
        if (p + pkt->p.sig_len > buf + len) return -1;
        memcpy(pkt->p.sig_bytes, p, pkt->p.sig_len); p += pkt->p.sig_len;
        // print_hex("pkt.p.sig_bytes", pkt->p.sig_bytes, pkt->p.sig_len);
    } else if (pkt->h.status == SETUP_RESP) {
        // π_list
        if (p + MAX_PI > buf + len) return -1;
        memcpy(pkt->h.pi_concat, p, MAX_PI); //πリストは固定長で受け取る
        p += MAX_PI;

        // ρ
        if (p + SIG_LEN * 2 > buf + len) return -1;
        memcpy(pkt->h.rho, p, SIG_LEN * 2); p += SIG_LEN * 2;
        // print_hex("rho", pkt->h.rho, SIG_LEN*2);

        // rand_val + peer_pub
        if (p + 4 > buf + len) return -1;
        memcpy(pkt->p.rand_val, p, 4); p += 4;
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
    } else if (pkt->h.status == DATA_TRANS) {
        // payload: IV + CT_LEN + CT + TAG
        if (p + 12 > buf + len) return -1;
        memcpy(pkt->p.iv, p, 12); p += 12;
        pkt->p.ct_len = ntohs(*(uint16_t*)p); p += 2;
        if (p + pkt->p.ct_len > buf + len) return -1;
        memcpy(pkt->p.ct, p, pkt->p.ct_len); p += pkt->p.ct_len;
        if (p + 16 > buf + len) return -1;
        memcpy(pkt->p.tag, p, 16); p += 16;
    } else {
        return -1; // 未知のステータス
    }
    return 0;
}

// ルータ処理（SETUP_REQの中継）
int router_handle_forward(unsigned char *frame, Node *nodes) {
    Packet pkt;
    size_t frame_cap = MAX_FRAME;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    size_t m_len, n_len, m2_len;
    unsigned char *m = NULL, *n = NULL, *m2 = NULL;
    unsigned char pi[SIG_LEN], tau[SIG_LEN];
    size_t pi_len = SIG_LEN, tau_len = SIG_LEN;

    if (pkt.h.status != SETUP_REQ) { fprintf(stderr,"unexpected status\n"); return -1; }

    unsigned char sid_chk[SID_LEN];
    // print_hex("pkt.h.sid", pkt.h.sid, SID_LEN);
    hash_sid_from_pub(pkt.p.peer_pub, sid_chk);
    if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
        fprintf(stderr,"SID verify failed at R%d\n", idx);
        return -1;
    }

    unsigned char precid[CID_LEN]; 
    memcpy(precid, pkt.h.cid, CID_LEN);
    // 新しいサーキットIDをランダム生成
    RAND_bytes(pkt.h.cid, CID_LEN);

    // 経路情報復号
    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char sharec[SEC_LEN];
    derive_shared(me->dh_sk, C_pub, sharec);
    memcpy(me->ki, sharec, KEY_LEN);
    // print_hex("ki", me->ki, KEY_LEN);

    size_t segoff = (me->id - 1) * (SEG_LEN + TAG_LEN + IV_LEN);
    const unsigned char *ci  = pkt.h.seg_concat + segoff;
    // print_hex("ci", ci, SEG_LEN);
    const unsigned char *tag = pkt.h.seg_concat + segoff + SEG_LEN;
    // print_hex("tag", tag, TAG_LEN);
    const unsigned char *iv  = pkt.h.seg_concat + segoff + SEG_LEN + TAG_LEN;
    // print_hex("iv", iv, IV_LEN);

    // 共有鍵 k_i で復号
    unsigned char plain[12];  // 復号結果を格納（12バイト＋α）
    if (!aead_decrypt(me->ki, ci, SEG_LEN, pkt.h.sid, iv, tag, plain))
        die("GCM auth fail (seg decrypt)");
    // printf("got plaintext: %s\n", plain);
    // print_hex("Decrypted segment", plain, 12);
    
    //復号結果を分割
    // 結果を分割: IPv4アドレス3つ分 (各4バイト)
    unsigned char prev_addr[4], next_addr[4], nnext_addr[4];
    memcpy(prev_addr,  plain,     4);
    memcpy(next_addr,  plain + 4, 4);
    memcpy(nnext_addr, plain + 8, 4);
    // printf("prev_addr: %u.%u.%u.%u\n", prev_addr[0], prev_addr[1], prev_addr[2], prev_addr[3]);
    // printf("next_addr: %u.%u.%u.%u\n", next_addr[0], next_addr[1], next_addr[2], next_addr[3]);
    // printf("nnext_addr: %u.%u.%u.%u\n", nnext_addr[0], nnext_addr[1], nnext_addr[2], nnext_addr[3]);


    //******アドレスからidxを引く
    int prev_idx = prev_addr[3];//get_node_idx(prev_addr, nodes);
    int next_idx = next_addr[3];//get_node_idx(next_addr, nodes);
    int nnext_idx = nnext_addr[3];//get_node_idx(nnext_addr, nodes);

    // 前ノードの τ_{i-1} を検証
    m = concat2(pkt.h.sid, SID_LEN, nodes[prev_idx].addr, sizeof(nodes[prev_idx].addr), &m_len);
    if (!verify_sig(nodes[prev_idx].pk, m, m_len, pkt.p.tau, SIG_LEN)) {//pkt.p.tau_len)) {
        fprintf(stderr, "Verify τ%d failed\n", prev_idx);
        free(m);
        return -1;
    }
    printf("Verify τ%d success\n", prev_idx);
    free(m);

    // π_i = Sign(sk_i, τ_{i-1} || r_i)
    n = concat2(pkt.p.tau, SIG_LEN, me->rand_val, sizeof(me->rand_val), &n_len);
    print_hex("n", n, n_len);
    sign_data(me->sk, n, n_len, pi, &pi_len);
    free(n);
    size_t offset = (idx - 1) * SIG_LEN;

    // if (pkt.h.pi_concat_len + pi_len > sizeof(pkt.h.pi_concat)) {
    if (offset + pi_len > sizeof(pkt.h.pi_concat)) {
        fprintf(stderr,"pi_concat overflow at R%d\n", idx);
        // OPENSSL_free(pi);
        return -1;
    }
    memcpy(pkt.h.pi_concat + offset, pi, pi_len);
    printf("π%d", idx);print_hex(" ", pi, pi_len);
    // OPENSSL_free(pi);

    // τ_i = Sign(sk_i, sid||addr) (サーバは除く)
    if (me->id != NODES-1) {
        m2 = concat2(pkt.h.sid, SID_LEN, me->addr, sizeof(me->addr), &m2_len);
        sign_data(me->sk, m2, m2_len, tau, &tau_len);
        free(m2);
        if (tau_len > SIG_LEN) { 
            // OPENSSL_free(tau); 
            fprintf(stderr,"tau_len too big\n"); return -1; }
        memcpy(pkt.p.tau, tau, tau_len);
        // printf("τ%d", idx); print_hex(" ", pkt->p.tau, pkt->p.tau_len);
        // OPENSSL_free(tau);

    }

    // 次のノードの位置を設定
    pkt.h.idx++;

    // ステート保存（prev=前ホップアドレス, next=次ホップアドレス or 自身）
    state_set(me, pkt.h.sid, precid, pkt.h.cid, prev_idx, next_idx, nnext_idx, pkt.p.tau, SIG_LEN);

    // フレーム再構築
    size_t wire_len = build_overlay_setup_req(frame, frame_cap, &pkt);
    printf("Forward frame wire_len=%zu pi_list_len=%u\n", wire_len, idx * SIG_LEN);
    return 0;
}

// ルータ処理（SETUP_RESPの中継）
int router_handle_reverse(unsigned char *frame, Node *nodes) {
    Packet pkt;
    size_t frame_cap = MAX_FRAME;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];

    if (pkt.h.status != SETUP_RESP) { fprintf(stderr,"unexpected status\n"); return -1; }

    // unsigned char precid[CID_LEN];
    // memcpy(precid, pkt.h.cid, CID_LEN);
    // if (memcmp(precid, me->state[0].nexcid, CID_LEN) != 0) {// 最初のステートだけ見てサーキットIDを比較
    //     fprintf(stderr,"Circuit ID mismatch\n");
    //     return -1;
    // }

    unsigned char rho[SIG_LEN];
    // ρ_i+2を検証
    if (idx + 2 <= NODES - 1) {
        if (idx % 2 == 0) {
            memcpy(rho, pkt.h.rho[0], SIG_LEN);
        } else {
            memcpy(rho, pkt.h.rho[1], SIG_LEN);
        }
        size_t n_len;
        unsigned char *n = NULL;
        n = concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &n_len);
        // print_hex("n", n, n_len);
        // print_hex("rho to verify", rho, SIG_LEN);
        if (!verify_sig(nodes[idx + 2].pk, n, n_len, rho, SIG_LEN)) {
            fprintf(stderr,"Verify ρ%d failed\n", idx + 2);
            free(n);
            return -1;
        }
        printf("Verify ρ%d success\n", idx + 2);
    }

    // π_i+1 を取り出す
    size_t nidx = idx + 1;
    if (nidx == 0) { fprintf(stderr,"invalid nidx\n"); return -1; }
    size_t offset = (nidx - 1) * SIG_LEN;
    // if (offset + SIG_LEN > pkt.h.pi_concat_len) { 
    if (offset + SIG_LEN > MAX_PI) { 
        fprintf(stderr,"pi_concat out of range\n"); 
        return -1; 
    }
    unsigned char *pi_next = pkt.h.pi_concat + offset;
    printf("π%d", pkt.h.idx + 1); print_hex("", pi_next, SIG_LEN);

    // τ_i を取り出す
    EVP_PKEY *sk = load_ed25519_seckey_pem("dh_sec.pem");
    // 公開鍵 raw を取得して SID を再計算
    unsigned char kC_pub[PUB_LEN];
    get_raw_pub(sk, kC_pub);
    unsigned char sid[SID_LEN];
    hash_sid_from_pub(kC_pub, sid);
    // print_hex("SID (Receiver)", sid, SID_LEN);
    // 受信側で τ4 を生成(復路の検証用 本来は state から取得)
    Node *ni = &nodes[pkt.h.idx];
    unsigned char t[SIG_LEN];
    size_t tau_len = SIG_LEN, g_len;
    unsigned char *g = concat2(sid, SID_LEN, ni->addr, 4, &g_len);
    print_hex("g", g, g_len);
    sign_data(ni->sk, g, g_len, t, &tau_len);
    print_hex("τ", t, tau_len);
    free(g);
    const unsigned char *tau = t;//state_get_tau(me, pkt.h.sid);
    if (!tau) { fprintf(stderr,"tau not found at R%d\n", idx); return -1; }

    // π_i+1 を検証
    size_t n_len;
    unsigned char *n = concat2(tau, SIG_LEN, pkt.p.rand_val, sizeof(pkt.p.rand_val), &n_len);
    if (!verify_sig(nodes[nidx].pk, n, n_len, pi_next, SIG_LEN)) {
        free(n); 
        fprintf(stderr,"Verify π%ld failed at R%d\n", nidx, idx); 
        return -1;
    }
    free(n);
    printf("Verify π%ld success \n", nidx);

    if (idx - 2 >= 0) {
        // ρ_iを生成
        size_t m_len, rho_len;
        unsigned char *m = NULL;
        m = concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &m_len);
        sign_data(me->sk, m, m_len, pkt.h.rho[idx % 2], &rho_len);
        free(m);
        // print_hex("ρ", pkt.h.rho, SIG_LEN*2);
    }
    

    pkt.h.idx--;

    // フレーム再構築(乱数を更新)
    memcpy(pkt.h.cid, me->state[0].precid, CID_LEN);
    memcpy(pkt.p.rand_val, me->rand_val, sizeof(me->rand_val));
    size_t wire_len = build_overlay_setup_resp(frame, frame_cap, &pkt);
    printf("Reverse frame wire_len=%zu rand_val updated\n", wire_len);
    return 0;
}

int apply_policy_contract(const char *msg) {
    if (!msg) return 0;
    for (int i = 0; i < POLICY_COUNT; i++) {
        if (strstr(msg, policy[i]) != NULL) {
            // 禁止ワード表示(英語で)
            printf("Detected: '%s'\n", policy[i]);
            return 1;
        }
    }
    return 0;
}


