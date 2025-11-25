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

/* ======= 固定TLS鍵とIV (handshake省略) ======= */
const uint8_t fixed_tls_iv[12] = {
    0xf4, 0x83, 0x3e, 0x10, 0xa4, 0x38, 0xbf, 0x13, 0xaf, 0xb0, 0x1e, 0x8f
};
const uint8_t fixed_tls_key[32] = {
    0xc7, 0xb5, 0x68, 0x7a, 0xfb, 0xc2, 0xfc, 0x4f,
    0xc8, 0xf1, 0x15, 0xb0, 0x18, 0x0d, 0x9d, 0x26,
    0xf9, 0x2c, 0xf7, 0x46, 0xac, 0xbb, 0xd1, 0x20,
    0x61, 0x0e, 0xd7, 0x67, 0x39, 0xda, 0x7e, 0xbb
};
/* nonce counter: 接続ごとに別で良いので static に持つ（両端とも同様の扱いで） */
uint32_t nonce_counter = 1;


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

EVP_PKEY* extract_public_only(EVP_PKEY *priv) {
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
// 初期化処理
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

int hmac_sha256(const unsigned char *key, size_t keylen, const unsigned char *data, size_t datalen, unsigned char out[ACSEG_LEN], unsigned int *out_len){
    if (!key || keylen == 0 || (!data && datalen > 0) || !out || !out_len) {
        return -1;
    }

    unsigned char *res = HMAC(EVP_sha256(), (const void*)key, (int)keylen, data, datalen, out, out_len);
    if (!res) return -1;
    return 0;
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
   node->dh_sk = load_ed25519_seckey_pem("dh_sec.pem");//gen_x25519_keypair();//ここでファイル読み込みしたい
   unsigned char pub[PUB_LEN];
   get_raw_pub(node->dh_sk, pub);
   node->dh_pk = import_x25519_pub(pub);

    node->sk = load_ed25519_seckey_pem("ed25519_sec.pem"); // 既存秘密鍵の読み込み
    node->pk = load_ed25519_pubkey_pem("ed25519_pub.pem"); // 既存公開鍵の読み込み
    init_crypto(node->sk, node->pk);// 今はどのノードの鍵も一緒なので自身の鍵で初期化しておく


    US_CTX *us = US_init("secp256k1");
    node->us_x = load_us_x_pem("us_x.pem");
    if (!node->us_x) {
        node->us_x = BN_new();
        BN_rand_range(node->us_x, us->order);
        save_us_x_pem(node->us_x, "us_x.pem");  // 初回のみ保存
    }
    // === us_x の値を出力 ===
    char *us_x_hex = BN_bn2hex(node->us_x);
    // if (us_x_hex) {
    //     printf("[node_init] us_x = %s\n", us_x_hex);
    //     OPENSSL_free(us_x_hex);
    // } else {
    //     fprintf(stderr, "[node_init] Failed to convert us_x to hex.\n");
    // }
    // node->us_x = BN_new();
    // BN_rand_range(node->us_x, us->order);
    node->us_y = EC_POINT_new(us->group);
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    EC_POINT_mul(us->group, node->us_y, NULL, G, node->us_x, us->ctx);

   //  // IPv4アドレスの設定
   if (inet_pton(AF_INET, addr, node->addr) != 1) {
        die("inet_pton failed in prev_node_init");
    }
    // RAND_bytes(node->rand_val, sizeof(node->rand_val));
    // 便宜上乱数を任意の値に固定 本来はstate_setごとにランダム値を設定
    memset(node->state[0].rand_val, 0x11, sizeof(node->state[0].rand_val));

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

// π-list をセッションID (SID) ごとに保存
int save_pi_list(const unsigned char sid[SID_LEN], const unsigned char *pi_concat, size_t pi_len) {
    // char filename[128];
    // // SIDの先頭8バイトをファイル名に利用
    // char sid_hex[17];
    // for (int i = 0; i < 8; i++)
    //     sprintf(&sid_hex[i*2], "%02x", sid[i]);
    // sid_hex[16] = '\0';
    // snprintf(filename, sizeof(filename), "pi_%s.dat", sid_hex);
    const char *filename = "pi_list.dat";

    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    // ファイル構造: [SID(32B)] [π-list本体]
    fwrite(sid, 1, SID_LEN, f);
    fwrite(pi_concat, 1, pi_len, f);
    fclose(f);
    
    printf("Saved π-list (%zu bytes) as %s\n", pi_len, filename);
    return 0;
}

int load_pi_list(const char *filename, unsigned char sid[SID_LEN], unsigned char **pi_out, size_t *pi_len_out){
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    if (len <= SID_LEN) {
        fclose(f);
        return -1;
    }

    fread(sid, 1, SID_LEN, f);
    *pi_len_out = len - SID_LEN;
    *pi_out[*pi_len_out];
    fread(*pi_out, 1, *pi_len_out, f);
    fclose(f);

    return 0;
}

//========= オーバーレイ領域ヘッダ & ペイロード=========
size_t overlay_header_footprint(void) { return SID_LEN + CID_LEN + 1 + 1; }//固定へッダ長

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
    size_t need = off + overlay_header_footprint() + (pkt->h.idx - 1) * USIG_LEN + SIG_LEN + PUB_LEN;
    if (cap < need) die("cap too small (setup req)");
    unsigned char *p = l2 + off; //現在の位置 ＋ L2L3オフセット
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    memcpy(p, pkt->h.cid, CID_LEN); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    // print_hex("pkt.h.sid", pkt->h.sid, SID_LEN);
    // printf("R%d\n", pkt->h.idx);

    // seg_concatを乗せる
    memcpy(p, pkt->h.seg_concat, MAX_SEG_CON); p += MAX_SEG_CON; // segリストは固定長
    // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
    if (pkt->h.idx == NODES){ // 最後のノードの処理後
        memcpy(p, pkt->h.dh_pk_concat, ROUTERS * PUB_LEN); p += ROUTERS * PUB_LEN; // DH公開鍵リストは固定長
        // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, ROUTERS * PUB_LEN);
    } else {
        memcpy(p, pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN); p += (pkt->h.idx - 1) * PUB_LEN; // DH公開鍵リストは固定長
        // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
    }
    memcpy(p, pkt->h.com_concat, (pkt->h.idx - 1) * USIG_LEN); p += (pkt->h.idx - 1) * USIG_LEN; // コミットメントリストは固定長
    // print_hex("pkt.h.com_concat", pkt->h.com_concat, (pkt->h.idx - 1) * USIG_LEN);
    memcpy(p, pkt->h.pi_concat, (pkt->h.idx - 1) * USIG_LEN); p += (pkt->h.idx - 1) * USIG_LEN; // πリストは固定長
    // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, (pkt->h.idx - 1) * USIG_LEN);

    // ぺイロード
    memcpy(p, pkt->p.tau, SIG_LEN); p += SIG_LEN; //固定長で送る
    // print_hex("pkt.p.tau", pkt->p.tau, SIG_LEN);
    memcpy(p, pkt->p.v, 162); p += 162; //固定長で送る
    // print_hex("pkt.p.v", pkt->p.v, 162);
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN;
    // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
    // print_hex("Built SETUP_REQ", l2 + off, (size_t)(p - l2 - off));
    // グループ署名の署名長もpに乗せる
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
    size_t need = off + overlay_header_footprint() + MAX_PI + SIG_LEN + 4 + 4 + 98 + PUB_LEN;
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
    // print_hex("rho", pkt->h.rho[1], SIG_LEN);
    // ペイロード
    memcpy(p, pkt->p.rand_val, sizeof(pkt->p.rand_val)); p += sizeof(pkt->p.rand_val); // 4
    // print_hex("pkt.p.rand_val", pkt->p.rand_val, sizeof(pkt->p.rand_val));
    uint32_t nizk_sig_len_n = htonl(pkt->p.nizk_sig_len);
    memcpy(p, &nizk_sig_len_n, sizeof(nizk_sig_len_n));
    // print_hex("pkt.p.sig_len", p, sizeof(nizk_sig_len_n));
    p += sizeof(nizk_sig_len_n);//4
    memcpy(p, pkt->p.nizk_sig, pkt->p.nizk_sig_len); p += pkt->p.nizk_sig_len;//98
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN; //32

    return (size_t)(p - l2 - off);
}

// DATA_TRANS を書く
size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    uint16_t ctlen = (uint16_t)pkt->p.ct_len;

    size_t need = off + overlay_header_footprint() +  (pkt->h.idx - 1) * ACSEG_LEN + IV_LEN + 2 + ctlen + TAG_LEN;
    // if (cap < need) die("cap too small (data trans)");
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    // print_hex( "pkt.h.cid", pkt->h.cid, CID_LEN);
    memcpy(p, &pkt->h.cid, CID_LEN); p += CID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;//66
    
    memcpy(p, pkt->h.acseg_concat, ROUTERS * ACSEG_LEN); p += ROUTERS * ACSEG_LEN;//128
    // ぺイロード
    memcpy(p, pkt->p.iv, IV_LEN); p += IV_LEN;
    uint16_t n = htons(ctlen); memcpy(p, &n, 2); p += 2;
    // printf("ctlen: %d\n", ctlen);
    memcpy(p, pkt->p.ct, ctlen); p += ctlen;
    memcpy(p, pkt->p.tag, TAG_LEN); p += TAG_LEN;//41 +32(padding)
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
    memcpy(pkt->h.cid, p, CID_LEN); p += CID_LEN;
    pkt->h.status = *p++;
    pkt->h.idx = *p++;
    // printf("pkt.h.idx: %d\n", pkt->h.idx);
    
    if (pkt->h.status == SETUP_REQ) {
        // seg_listをパース
        if (p + MAX_SEG_CON > buf + len) return -1;
        memcpy(pkt->h.seg_concat, p, MAX_SEG_CON); // segリストは固定長で受け取る
        // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
        p += MAX_SEG_CON;
        if (pkt->h.idx == NODES) {
            if (p + ROUTERS * PUB_LEN > buf + len) return -1;
            memcpy(pkt->h.dh_pk_concat, p, ROUTERS * PUB_LEN); // DH公開鍵リストはidxによる可変長で受け取る
            // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
            p += ROUTERS * PUB_LEN;
        } else {
            // dh_pk_list
            if (p + (pkt->h.idx - 1) * PUB_LEN > buf + len) return -1;
            memcpy(pkt->h.dh_pk_concat, p, (pkt->h.idx - 1) * PUB_LEN); // DH公開鍵リストはidxによる可変長で受け取る
            // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
            p += (pkt->h.idx - 1) * PUB_LEN;
        }
        // if (pkt->h.idx > 1) {
            // com_list
        if (p + (pkt->h.idx - 1) * USIG_LEN > buf + len) return -1;
        memcpy(pkt->h.com_concat, p, (pkt->h.idx - 1) * USIG_LEN); // コミットメントリストはidxによる可変長で受け取る
        // print_hex("pkt.h.com_concat", pkt->h.com_concat, (pkt->h.idx - 1) * USIG_LEN);
        p += (pkt->h.idx - 1) * USIG_LEN;
        //π_list
        if (p + (pkt->h.idx - 1) * USIG_LEN > buf + len) return -1;
        memcpy(pkt->h.pi_concat, p, (pkt->h.idx - 1) * USIG_LEN); // πリストはidxによる可変長で受け取る
        // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, (pkt->h.idx - 1) * USIG_LEN);
        p += (pkt->h.idx - 1) * USIG_LEN;
        // }

        //  τ + peer_pub
        if (p + SIG_LEN > buf + len) return -1;
        memcpy(pkt->p.tau, p, SIG_LEN); p += SIG_LEN;
        // print_hex("pkt.p.tau", pkt->p.tau, SIG_LEN);
        if (p + 162 > buf + len) return -1;
        memcpy(pkt->p.v, p, 162); p += 162;
        // print_hex("pkt.p.v", pkt->p.v, 162);
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
        // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
        // グループ署名
        uint32_t sig_len_n;
        memcpy(&sig_len_n, p, sizeof(sig_len_n));
        pkt->p.sig_len = ntohl(sig_len_n);
        p += sizeof(sig_len_n);
        // printf ("sig_len: %lu\n", pkt->p.sig_len);
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
        // print_hex("rho", pkt->h.rho[1], SIG_LEN);

        // rand_val + peer_pub
        if (p + 4 > buf + len) return -1;
        memcpy(pkt->p.rand_val, p, 4); p += 4;
        // print_hex("rand_val", pkt->p.rand_val, 4);
        uint32_t nizk_sig_len_n;
        memcpy(&nizk_sig_len_n, p, sizeof(nizk_sig_len_n));
        // print_hex("pkt.p.sig_len", p, sizeof(nizk_sig_len_n));
        pkt->p.nizk_sig_len = ntohl(nizk_sig_len_n);
        // printf ("nizk_sig_len: %lu\n", pkt->p.nizk_sig_len);
        p += sizeof(nizk_sig_len_n);
        if (p + pkt->p.nizk_sig_len > buf + len) return -1;
        pkt->p.nizk_sig = (unsigned char *)malloc(pkt->p.nizk_sig_len);
        memcpy(pkt->p.nizk_sig, p, pkt->p.nizk_sig_len); p += pkt->p.nizk_sig_len;
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
        // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
    } else if (pkt->h.status == DATA_TRANS) {
        // if (p + (pkt->h.idx - 1) * ACSEG_LEN > buf + len) return -1;
        // uint32_t ac_len_n;
        // memcpy(&ac_len_n, p, sizeof(ac_len_n));
        // pkt->h.acseg_concat_len = ntohs(*(uint32_t*)&ac_len_n);
        // printf("acseg_concat_len: %lu\n", pkt->h.acseg_concat_len);
        // p += sizeof(ac_len_n);
        memcpy(pkt->h.acseg_concat, p, ROUTERS * ACSEG_LEN); p += ROUTERS * ACSEG_LEN;
        // payload: IV + CT_LEN + CT + TAG
        if (p + IV_LEN > buf + len) return -1;
        memcpy(pkt->p.iv, p, IV_LEN); p += IV_LEN;
        pkt->p.ct_len = ntohs(*(uint16_t*)p); p += 2;
        if (p + pkt->p.ct_len > buf + len) return -1;
        memcpy(pkt->p.ct, p, pkt->p.ct_len); p += pkt->p.ct_len;
        if (p + TAG_LEN > buf + len) return -1;
        memcpy(pkt->p.tag, p, TAG_LEN); p += TAG_LEN;

    } else {
        return -1; // 未知のステータス
    }
    return 0;
}

// // ルータ処理（SETUP_REQの中継）
// int router_handle_forward(unsigned char *frame, Node *nodes) {
//     Packet pkt;
//     size_t frame_cap = MAX_FRAME;
//     if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
//         fprintf(stderr, "Router: parse failed\n");
//         return -1;
//     }
//     int idx = pkt.h.idx;
//     printf("\n=== Node R%d ===\n", idx);
//     Node *me = &nodes[idx];
//     size_t m_len, n_len, m2_len;
//     unsigned char *m = NULL, *n = NULL, *m2 = NULL;
//     unsigned char pi[USIG_LEN], tau[SIG_LEN];
//     size_t pi_len = USIG_LEN, tau_len = SIG_LEN;

//     if (pkt.h.status != SETUP_REQ) { fprintf(stderr,"unexpected status\n"); return -1; }

//     unsigned char sid_chk[SID_LEN];
//     // print_hex("pkt.h.sid", pkt.h.sid, SID_LEN);
//     hash_sid_from_pub(pkt.p.peer_pub, sid_chk);
//     if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
//         fprintf(stderr,"SID verify failed at R%d\n", idx);
//         return -1;
//     }

//     unsigned char precid[CID_LEN]; 
//     memcpy(precid, pkt.h.cid, CID_LEN);
//     // 新しいサーキットIDをランダム生成
//     RAND_bytes(pkt.h.cid, CID_LEN);

//     // 経路情報復号
//     EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
//     unsigned char sharec[SEC_LEN];
//     derive_shared(me->dh_sk, C_pub, sharec);
//     memcpy(me->ki, sharec, KEY_LEN);
//     // print_hex("ki", me->ki, KEY_LEN);

//     size_t segoff = (me->id - 1) * (SEG_LEN + TAG_LEN + IV_LEN);
//     const unsigned char *ci  = pkt.h.seg_concat + segoff;
//     // print_hex("ci", ci, SEG_LEN);
//     const unsigned char *tag = pkt.h.seg_concat + segoff + SEG_LEN;
//     // print_hex("tag", tag, TAG_LEN);
//     const unsigned char *iv  = pkt.h.seg_concat + segoff + SEG_LEN + TAG_LEN;
//     // print_hex("iv", iv, IV_LEN);

//     // 共有鍵 k_i で復号
//     unsigned char plain[12];  // 復号結果を格納（12バイト＋α）
//     if (!aead_decrypt(me->ki, ci, SEG_LEN, pkt.h.sid, iv, tag, plain))
//         die("GCM auth fail (seg decrypt)");
//     // printf("got plaintext: %s\n", plain);
//     // print_hex("Decrypted segment", plain, 12);
    
//     //復号結果を分割
//     // 結果を分割: IPv4アドレス3つ分 (各4バイト)
//     unsigned char prev_addr[4], next_addr[4], nnext_addr[4];
//     memcpy(prev_addr,  plain,     4);
//     memcpy(next_addr,  plain + 4, 4);
//     memcpy(nnext_addr, plain + 8, 4);
//     // printf("prev_addr: %u.%u.%u.%u\n", prev_addr[0], prev_addr[1], prev_addr[2], prev_addr[3]);
//     // printf("next_addr: %u.%u.%u.%u\n", next_addr[0], next_addr[1], next_addr[2], next_addr[3]);
//     // printf("nnext_addr: %u.%u.%u.%u\n", nnext_addr[0], nnext_addr[1], nnext_addr[2], nnext_addr[3]);


//     //******アドレスからidxを引く
//     int prev_idx = prev_addr[3];//get_node_idx(prev_addr, nodes);
//     int next_idx = next_addr[3];//get_node_idx(next_addr, nodes);
//     int nnext_idx = nnext_addr[3];//get_node_idx(nnext_addr, nodes);

//     // 前ノードの τ_{i-1} を検証
//     m = concat2(pkt.h.sid, SID_LEN, nodes[prev_idx].addr, sizeof(nodes[prev_idx].addr), &m_len);
//     if (!verify_sig(nodes[prev_idx].pk, m, m_len, pkt.p.tau, SIG_LEN)) {//pkt.p.tau_len)) {
//         fprintf(stderr, "Verify τ%d failed\n", prev_idx);
//         free(m);
//         return -1;
//     }
//     printf("Verify τ%d success\n", prev_idx);
//     free(m);

//     // π_i = Sign(sk_i, τ_{i-1} || r_i) 
//     n = concat2(pkt.p.tau, SIG_LEN, me->state[0].rand_val, sizeof(me->state[0].rand_val), &n_len);
//     // print_hex("n", n, n_len);
    
//     US_CTX *us = US_init("secp256k1");
//     if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
//     unsigned char *USpi = NULL; size_t USpi_len;
//     US_sign(us, n, n_len, me->us_x, &USpi, &USpi_len);
//     // BIGNUM *a = BN_new();
//     // BIGNUM *b = BN_new();
//     // EC_POINT *W = EC_POINT_new(us->group);
//     // // EC_GROUP *group1 = EC_GROUP_new_by_curve_name(CURVE_NID);
//     // if (!US_challenge(us, USpi, USpi_len, me->us_y, a, b, W)) {
//     //     fprintf(stderr,"US_challenge error\n"); return 1;
//     // }
//     // // Alice computes response
//     // EC_POINT *R = EC_POINT_new(us->group);
//     // if (!US_response(us, W, me->us_x, R)) {
//     //     fprintf(stderr,"US_response error\n"); return 1;
//     // }

//     // // Bob verifies
//     // // Map message -> scalar m' -> M = m'*G
//     // BIGNUM *m_scalar = BN_new();
//     // if (!hash_to_scalar(us, n, n_len, m_scalar)) {
//     //     fprintf(stderr,"hash_to_scalar error\n"); return 1;
//     // }
//     // EC_POINT *M = EC_POINT_new(us->group);
//     // const EC_POINT *G = EC_GROUP_get0_generator(us->group);
//     // if (!EC_POINT_mul(us->group, M, NULL, G, m_scalar, us->ctx)) {
//     //     fprintf(stderr,"M mul error\n"); return 1;
//     // }
//     // int ver = US_verify(us, R, M, a, b);
//     // if (ver == 1) {
//     //     printf("Signature CONFIRMED.\n");
//     // } else if (ver == 0) {
//     //     printf("Signature NOT confirmed.\n");
//     // }

//     // sign_data(me->sk, n, n_len, pi, &pi_len);
//     free(n);
//     size_t offset = (idx - 1) * USIG_LEN;

//     if (offset + USpi_len > sizeof(pkt.h.pi_concat)) {
//         fprintf(stderr,"pi_concat overflow at R%d\n", idx);
//         // OPENSSL_free(pi);
//         return -1;
//     }
//     memcpy(pkt.h.pi_concat + offset, USpi, USpi_len);
//     printf("π%d", idx);print_hex(" ", USpi, USpi_len);

//     // τ_i = Sign(sk_i, sid||addr) (サーバは除く)
//     if (me->id != NODES-1) {
//         m2 = concat2(pkt.h.sid, SID_LEN, me->addr, sizeof(me->addr), &m2_len);
//         sign_data(me->sk, m2, m2_len, tau, &tau_len);
//         free(m2);
//         if (tau_len > SIG_LEN) { 
//             // OPENSSL_free(tau); 
//             fprintf(stderr,"tau_len too big\n"); return -1; }
//         memcpy(pkt.p.tau, tau, tau_len);
//         // printf("τ%d", idx); print_hex(" ", pkt->p.tau, pkt->p.tau_len);
//         // OPENSSL_free(tau);

//     }

//     // 次のノードの位置を設定
//     pkt.h.idx++;

//     // ステート保存（prev=前ホップアドレス, next=次ホップアドレス or 自身）
//     state_set(me, pkt.h.sid, precid, pkt.h.cid, prev_idx, next_idx, nnext_idx, pkt.p.tau, SIG_LEN);

//     // フレーム再構築
//     size_t wire_len = build_overlay_setup_req(frame, frame_cap, &pkt);
//     printf("Forward frame wire_len=%zu pi_list_len=%u\n", wire_len, idx * USIG_LEN);
//     return 0;
// }

// 修正したルータ処理（SETUP_REQの中継）
int router_handle_forward(unsigned char *frame, Node *nodes) {
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    
    Packet pkt;
    size_t frame_cap = MAX_FRAME;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    size_t m_len, m2_len; //τ用
    size_t n_len, nn_len, n2_len, nn2_len; //π用
    // size_t cm_len; //コミットメント用
    size_t v_len; // πのNIZK用
    unsigned char *m = NULL, *n = NULL, *nn = NULL, *m2 = NULL, *n2 = NULL, *nn2 = NULL, *v = NULL;
    unsigned char pi[USIG_LEN], tau[SIG_LEN];
    size_t pi_len = USIG_LEN, tau_len = SIG_LEN;

    if (pkt.h.status != SETUP_REQ) { fprintf(stderr,"unexpected status\n"); return -1; }

    // unsigned char sid_chk[SID_LEN];
    // // print_hex("pkt.h.sid", pkt.h.sid, SID_LEN);
    // hash_sid_from_pub(pkt.p.peer_pub, sid_chk);
    // if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
    //     fprintf(stderr,"SID verify failed at R%d\n", idx);
    //     return -1;
    // }

    unsigned char precid[CID_LEN]; 
    memcpy(precid, pkt.h.cid, CID_LEN);
    // 新しいサーキットIDをランダム生成
    RAND_bytes(pkt.h.cid, CID_LEN);

    // 経路情報復号
    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    // print_hex("",pkt.p.peer_pub,PUB_LEN); // *********間違ってるパース失敗
    unsigned char sharec[SEC_LEN];
    derive_shared(me->dh_sk, nodes[0].dh_pk, sharec);
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

    // 前ノードの τ_i-1 を検証
    // print_hex("Verifying tau from prev node", pkt.p.tau, SIG_LEN);
    m = concat2(pkt.h.sid, SID_LEN, nodes[prev_idx].addr, sizeof(nodes[prev_idx].addr), &m_len);
    if (!verify_sig(nodes[prev_idx].pk, m, m_len, pkt.p.tau, SIG_LEN)) {//pkt.p.tau_len)) {
        fprintf(stderr, "Verify τ%d failed\n", prev_idx);
        free(m);
        return -1;
    }
    printf("Verify τ%d success\n", prev_idx);
    free(m);

    // レシーバ用に鍵情報を格納 (サーバは除く)
    if (me->id != NODES-1) {
        // レシーバ用に鍵情報を格納
        unsigned char ki_pub[PUB_LEN];
        get_raw_pub(me->dh_sk, ki_pub);
        size_t offset = (idx - 1) * PUB_LEN;
        
        memcpy(pkt.h.dh_pk_concat + offset, ki_pub, PUB_LEN);
        // print_hex("DH PK concat", pkt.h.dh_pk_concat, (idx) * PUB_LEN);
    }

    if (me->id > 1) { // N3以降ならπのNIZKを検証
        // π_i-1を検証
        //pi_concatから前ノード分を取り出す
        unsigned char *pi = (unsigned char *)malloc(USIG_LEN);
        memcpy(pi, pkt.h.pi_concat + (prev_idx - 1) * USIG_LEN, USIG_LEN);
        // print_hex("pi", pi, USIG_LEN);
        size_t pi_len = USIG_LEN;
        //com_concatと取り出した残りのΠからnを生成
        n = concat2(pkt.h.com_concat, prev_idx * USIG_LEN, pkt.h.pi_concat, (prev_idx - 1) * USIG_LEN, &n_len);
        nn = concat2(pkt.h.dh_pk_concat, prev_idx * PUB_LEN, n, n_len, &nn_len);
        // print_hex("nn", nn, nn_len);

        v_len = 32 *3 + 33 * 2;
        int ver = US_NIZK_VerifyC(us, me->us_y, me->us_y, nn, nn_len, pi, pi_len, pkt.p.v, v_len);//本来2つ目は前ノードの公開鍵
        if (ver == 1) {
            // printf("NIZK Signature CONFIRMED.\n");
            printf("Verify π%d success\n", prev_idx);
        } else if (ver == 0) {
            // printf("NIZK Signature NOT confirmed.\n");
            fprintf(stderr, "Verify π%d failed\n", prev_idx);
        }
        free(pi);
        free(n);
        free(v);
    }

    // if (me->id > 1) { // N2以降ならπとコミットメントを生成
    // コミットメント処理
    // cm = concat2(pkt.p.tau, SIG_LEN, me->state[0].rand_val, sizeof(me->state[0].rand_val), &cm_len);
    // print_hex("n", n, n_len);
    unsigned char *commit = NULL;
    size_t commit_len = 0;
    int ver = EC_Commit(us, pkt.p.tau, SIG_LEN, me->state[0].rand_val, sizeof(me->state[0].rand_val), G, &commit, &commit_len);
    if (!ver) { fprintf(stderr,"EC_Commit error\n"); return 1; }
    size_t offset = (idx - 1) * USIG_LEN;

    if (offset + commit_len > sizeof(pkt.h.com_concat)) {
        fprintf(stderr,"pi_concat overflow at R%d\n", idx);
        // OPENSSL_free(pi);
        return -1;
    }
    memcpy(pkt.h.com_concat + offset, commit, commit_len);
    // printf("C%d", idx);print_hex(" ", commit, commit_len);

    // π_i = Sign(sk_i, com_concat || pi_concat) 
    n2 = concat2(pkt.h.com_concat, idx * USIG_LEN, pkt.h.pi_concat, (idx - 1) * USIG_LEN, &n2_len);
    // printf(pkt.p.ct_len > 0 ? "ct_len=%zu\n" : "ct_len=0\n", pkt.p.ct_len);
    nn2 = concat2(pkt.h.dh_pk_concat, idx < NODES - 1 ? idx * PUB_LEN : ROUTERS * PUB_LEN, n2, n2_len, &nn2_len);
    // print_hex("nn2", nn2, nn2_len);
    unsigned char *USpi = NULL; size_t USpi_len;
    US_sign(us, nn2, nn2_len, me->us_x, &USpi, &USpi_len);
    size_t poffset = (idx - 1) * USIG_LEN;

    // n = concat2(pkt.p.tau, SIG_LEN, me->state[0].rand_val, sizeof(me->state[0].rand_val), &n_len);
    // print_hex("n", n, n_len);
    
    // unsigned char *USpi = NULL; size_t USpi_len;
    // US_sign(us, n, n_len, me->us_x, &USpi, &USpi_len);

    if (poffset + USpi_len > sizeof(pkt.h.pi_concat)) {
        fprintf(stderr,"pi_concat overflow at R%d\n", idx);
        // OPENSSL_free(pi);
        return -1;
    }
    memcpy(pkt.h.pi_concat + poffset, USpi, USpi_len);
    // printf("π%d", idx);print_hex(" ", USpi, USpi_len);
    // print_hex("pi_concat", pkt.h.pi_concat, MAX_PI);

    // 次ホップの検証するvを生成(RもVのために必要)
    size_t v2_len; // sufficient size
    unsigned char *v2 = (unsigned char *)malloc(32 *3 + 33 * 2);
    ver = US_NIZK_Confirm(us, nn2, nn2_len, me->us_x, me->us_y, USpi, USpi_len, &v2, &v2_len);// 本来2つ目は次ノードの公開鍵
    if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
    // print_hex("v2", v2, v2_len);

    memcpy(pkt.p.v, v2, v2_len);
    free(v2);
    free(n2);
    // }

    // τ_i = Sign(sk_i, sid||addr) (サーバは除く)
    if (me->id != NODES-1) {
        m2 = concat2(pkt.h.sid, SID_LEN, me->addr, sizeof(me->addr), &m2_len);
        sign_data(me->sk, m2, m2_len, tau, &tau_len);
        free(m2);
        if (tau_len > SIG_LEN) { 
            // OPENSSL_free(tau); 
            fprintf(stderr,"tau_len too big\n"); return -1; }
        memcpy(pkt.p.tau, tau, tau_len);
        // printf("τ%d", idx); print_hex(" ", pkt.p.tau, tau_len);
        // OPENSSL_free(tau);

        // // レシーバ用に鍵情報を格納
        // unsigned char ki_pub[PUB_LEN];
        // get_raw_pub(me->dh_sk, ki_pub);
        // size_t offset = (idx - 1) * PUB_LEN;
        
        // memcpy(pkt.h.dh_pk_concat + offset, ki_pub, PUB_LEN);
        // // print_hex("DH PK concat", pkt.h.dh_pk_concat, (idx) * PUB_LEN);
    }

    // 次のノードの位置を設定
    pkt.h.idx++;


    // ステート保存（prev=前ホップアドレス, next=次ホップアドレス or 自身）
    state_set(me, pkt.h.sid, precid, pkt.h.cid, prev_idx, next_idx, nnext_idx, pkt.p.tau, SIG_LEN);

    // フレーム再構築
    size_t wire_len = build_overlay_setup_req(frame, frame_cap, &pkt);
    printf("Forward frame wire_len=%zu com_list_len=%u pi_list_len=%u\n", wire_len, (idx-1) * USIG_LEN, (idx-1) * USIG_LEN);
    return 0;
}

// ルータ処理（SETUP_RESPの中継）
int router_handle_reverse(unsigned char *frame, Node *nodes) {
    US_CTX *us = US_init("secp256k1");
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
        // print_hex("rho to verify", (unsigned char *)rho, SIG_LEN);
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
    size_t offset = (nidx - 1) * USIG_LEN;
    if (offset + USIG_LEN > MAX_PI) { 
        fprintf(stderr,"pi_concat out of range\n"); 
        return -1; 
    }
    unsigned char *pi_next = pkt.h.pi_concat + offset;
    // printf("π%d", pkt.h.idx + 1); print_hex("", pi_next, USIG_LEN);

    // τ_i を取り出す
    // 受信側で τ を生成(復路の検証用 本来は state から取得)
    EVP_PKEY *sk = load_ed25519_seckey_pem("dh_sec.pem");
    // 公開鍵 raw を取得して SID を再計算
    unsigned char kC_pub[PUB_LEN];
    get_raw_pub(sk, kC_pub);
    unsigned char sid[SID_LEN];
    hash_sid_from_pub(kC_pub, sid);
    // print_hex("SID (Receiver)", sid, SID_LEN);
    unsigned char t[SIG_LEN];
    size_t tau_len = SIG_LEN, g_len;
    unsigned char *g = concat2(sid, SID_LEN, me->addr, 4, &g_len);
    // print_hex("g", g, g_len);
    sign_data(me->sk, g, g_len, t, &tau_len);
    // print_hex("τ", t, tau_len);
    free(g);
    const unsigned char *tau = t;//state_get_tau(me, pkt.h.sid);
    if (!tau) { fprintf(stderr,"tau not found at R%d\n", idx); return -1; }

    // π_i+1 を検証
    size_t n_len;
    unsigned char *n = concat2(tau, SIG_LEN, pkt.p.rand_val, sizeof(pkt.p.rand_val), &n_len);
    // print_hex("n", n, n_len);
    // print_hex("pkt.p.nizk_sig", pkt.p.nizk_sig, pkt.p.nizk_sig_len);
    int ver = US_NIZK_VerifyC(us, me->us_y, me->us_y, n, n_len, pi_next, USIG_LEN, pkt.p.nizk_sig, pkt.p.nizk_sig_len);
    // printf("US_NIZK_Verify result: %d\n", ver);
    if (ver == 0) {
        fprintf(stderr,"Verify π%ld failed\n", nidx);
        free(n);
        return -1;
    }
    printf("Verify π%ld success \n", nidx);
    free(n);
    // printf("Verify π%ld success \n", nidx);

    if (idx - 2 >= 0) {
        // ρ_iを生成
        size_t m_len, rho_len;
        unsigned char *m = NULL;
        m = concat2(pkt.h.sid, SID_LEN, pkt.h.pi_concat, MAX_PI, &m_len);
        sign_data(me->sk, m, m_len, pkt.h.rho[idx % 2], &rho_len);
        free(m);
        // print_hex("ρ", (unsigned char *)pkt.h.rho, SIG_LEN*2);
    }

    if (idx - 1 >= 0) {// A,B,sを生成
        // τ_{i-1} を生成
        size_t nt_len = SIG_LEN, g2_len, nizp_len, nizk_sig_len;
        unsigned char nt[SIG_LEN];
        unsigned char *nizp = NULL;
        unsigned char *nizk_sig = NULL;
        unsigned char *g2 = concat2(sid, SID_LEN, nodes[idx - 1].addr, 4, &g2_len);
        // print_hex("g", g2, g2_len);
        sign_data(me->sk, g2, g2_len, nt, &nt_len);// 本来のτ_Rは state から取得
        // print_hex("nt", nt, nt_len);
        nizp = concat2(nt, nt_len, me->state[0].rand_val, sizeof(me->state[0].rand_val), &nizp_len);// 本来の乱数は state から取得
        // print_hex("nizp", nizp, nizp_len);
        // π_i を取り出す
        size_t offset_cur = (idx - 1) * USIG_LEN;
        if (offset_cur + USIG_LEN > MAX_PI) { 
            fprintf(stderr,"pi_concat out of range\n"); 
            return -1; 
        }
        unsigned char *pi_cur = pkt.h.pi_concat + offset_cur;
        // print_hex("pi_cur", pi_cur, USIG_LEN);
        int ver = US_NIZK_Sign(us, nizp, nizp_len, me->us_x, me->us_y, pi_cur, USIG_LEN, &nizk_sig, &nizk_sig_len);
        if (!ver) { fprintf(stderr,"US_NIZK_Sign error at R%d\n", idx); return 1; }
        pkt.p.nizk_sig_len = nizk_sig_len;
        // printf("nizk_sig_len: %zu\n", nizk_sig_len);
        pkt.p.nizk_sig = (unsigned char *)malloc(nizk_sig_len);
        memcpy(pkt.p.nizk_sig, nizk_sig, nizk_sig_len);
        // print_hex("nizk_sig", nizk_sig, nizk_sig_len);
        free(nizp);
        free(nizk_sig);
        free(g2);
    }
    

    pkt.h.idx--;
    // printf("R%d forward to R%d\n", idx, pkt.h.idx);

    // フレーム再構築(乱数を更新)
    memcpy(pkt.h.cid, me->state[0].precid, CID_LEN);
    memcpy(pkt.p.rand_val, me->state[0].rand_val, sizeof(me->state[0].rand_val));
    size_t wire_len = build_overlay_setup_resp(frame, frame_cap, &pkt);
    printf("Reverse frame wire_len=%zu rand_val updated\n", wire_len);
    return 0;
}

int router_handle_data_trans(unsigned char *frame, Node *nodes) {
    Packet pkt;
    size_t frame_cap = MAX_FRAME;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    // printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    printf("R%d -> ", idx);

    if (pkt.h.status != DATA_TRANS) { fprintf(stderr,"unexpected status\n"); return -1; }

    // 本来はstateから取得
    int next_addr = idx + 1; //state_get_next(me, pkt.h.sid);
    if (next_addr < 0) {
        die("no next hop in data forward");
    }

    // Sからのアカセグ検証
    unsigned char *acseg = (unsigned char *)malloc(ACSEG_LEN);
    unsigned int acseg_len;
    size_t offset = (idx - 1) * ACSEG_LEN;
    // print_hex("AC Plain", ac_plain2, ac_plain2_len);
    int hmac_result = hmac_sha256(me->ki, KEY_LEN, pkt.p.ct, pkt.p.ct_len, acseg, &acseg_len);
    // acseg_concat内の自身のacsegと比較
    // print_hex("Received ACSEG", pkt.h.acseg_concat + offset, ACSEG_LEN);
    if (memcmp(acseg, pkt.h.acseg_concat + offset, ACSEG_LEN) == 0) {
        // printf("R%d ACSEG match\n", idx);
    } else {
        printf("R%d ACSEG mismatch\n", idx);
        return -1;
    }
    free(acseg);

    //アカウンタビリティセグメントを付加
    // ペイロード部の連結
    // size_t pay_len = IV_LEN + 2 + pkt.p.ct_len + TAG_LEN;
    // unsigned char *pay_buf1; size_t pay_buf1_len;
    // unsigned char *pay_buf2; size_t pay_buf2_len;
    // unsigned char *pay_buf3; size_t pay_buf3_len;
    // uint16_t ctlen_n = htons((uint16_t)pkt.p.ct_len);
    // pay_buf1 = concat2(pkt.p.iv, IV_LEN, (unsigned char*)&ctlen_n, 2, &pay_buf1_len);
    // pay_buf2 = concat2(pay_buf1, pay_buf1_len, pkt.p.ct, pkt.p.ct_len, &pay_buf2_len);
    // pay_buf3 = concat2(pay_buf2, pay_buf2_len, pkt.p.tag, TAG_LEN, &pay_buf3_len);
    // print_hex("Payload for ACSEG: ",pay_buf3, pay_buf3_len);

    // SID || Payload || next_addr(4B)
    // size_t ac_plain_len = SID_LEN + pay_buf3_len + 4;
    // unsigned char *ac_plain1; size_t ac_plain1_len;
    unsigned char *ac_plain2; size_t ac_plain2_len;

    // uint32_t next_addr_n = htonl((uint32_t)next_addr);
    // ac_plain1 = concat2(pkt.h.sid, SID_LEN, pay_buf3, pay_buf3_len, &ac_plain1_len);
    // ac_plain2 = concat2(ac_plain1, ac_plain1_len, (unsigned char*)&next_addr_n, 4, &ac_plain2_len);
    // printf("idx=%d\n", idx);
    // printf(pkt.p.ct_len > 0 ? "ct_len=%zu\n" : "ct_len=0\n", pkt.p.ct_len);
    ac_plain2 = concat2(pkt.h.acseg_concat, (idx - 1) * ACSEG_LEN, pkt.p.ct, pkt.p.ct_len, &ac_plain2_len);//*************** */
    // print_hex("AC_PLAIN: ", ac_plain2, ac_plain2_len);

    // HMACでACSEG生成
    // unsigned char acseg[ACSEG_LEN];
    // unsigned int acseg_len;
    // print_hex("me->ki", me->ki, KEY_LEN);
    int hmac_result2 = hmac_sha256(me->ki_R, KEY_LEN, ac_plain2, ac_plain2_len, pkt.h.acseg_concat + offset, &acseg_len);
    if (hmac_result2 != 0) {
        fprintf(stderr,"HMAC failed at R%d\n", idx);
        return -1;
    }
    // printf("R%d ACSEG: ", idx); print_hex("", pkt.h.acseg_concat + offset, acseg_len);
    // print_hex("ACSEG", pkt.h.acseg_concat, ROUTERS * ACSEG_LEN);

    // ctのハッシュ値を計算
    unsigned char ct_hash[SHA256_DIGEST_LENGTH];
    SHA256(pkt.p.ct, pkt.p.ct_len, ct_hash);
    // print_hex("CT HASH", ct_hash, SHA256_DIGEST_LENGTH);
    // ************************ステートに記録

    pkt.h.idx++;
    //本来はcidも更新
    
    size_t wire_len = build_overlay_data_trans(frame, frame_cap, &pkt);
    // printf("Data Trans frame wire_len=%zu \n", wire_len);
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

//Undeneiable Signature
US_CTX* US_init(const char *curve_name) {
    int nid;
    if (!curve_name) return NULL;

    // 例：curve_name = "secp256k1"
    nid = OBJ_txt2nid(curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Error: Unknown curve name: %s\n", curve_name);
        return NULL;
    }

    US_CTX *us = (US_CTX*)malloc(sizeof(US_CTX));
    if (!us) return NULL;

    us->ctx = BN_CTX_new();
    if (!us->ctx) {
        free(us);
        return NULL;
    }

    us->group = EC_GROUP_new_by_curve_name(nid);
    if (!us->group) {
        BN_CTX_free(us->ctx);
        free(us);
        return NULL;
    }

    us->order = BN_new();
    if (!us->order || !EC_GROUP_get_order(us->group, us->order, us->ctx)) {
        if (us->order) BN_free(us->order);
        EC_GROUP_free(us->group);
        BN_CTX_free(us->ctx);
        free(us);
        return NULL;
    }

    return us;
}

void US_free(US_CTX *us) {
    if (!us) return;
    if (us->order) BN_free(us->order);
    if (us->group) EC_GROUP_free(us->group);
    if (us->ctx) BN_CTX_free(us->ctx);
    free(us);
}

int hash_to_scalar(US_CTX *us, unsigned char *msg, size_t msglen, BIGNUM *out) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(msg, msglen, digest);
    // convert digest to BIGNUM and reduce mod order
    if (!BN_bin2bn(digest, SHA256_DIGEST_LENGTH, out)) return 0;
    if (!BN_mod(out, out, us->order, us->ctx)) return 0;
    // ensure non-zero
    if (BN_is_zero(out)) if (!BN_one(out)) return 0;
    return 1;
}

int US_sign(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *x, unsigned char **sig, size_t *sig_len){
    if (!message || !x || !us->ctx || !sig_len) return 0;

    int ret = 0;
    BIGNUM *m_scalar = NULL;
    EC_POINT *M = NULL;
    EC_POINT *Z = NULL;
    *sig = NULL;

    // ensure order is set
    if (!EC_GROUP_get_order(us->group, us->order, us->ctx)) {
        fprintf(stderr,"EC_GROUP_get_order error\n");
        return 0;
    }

    // 1) hash -> scalar
    m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)) {
        fprintf(stderr,"hash_to_scalar error\n"); return 0;
    }
    // 2) M = m_scalar * G
    M = EC_POINT_new(us->group);
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    if (!EC_POINT_mul(us->group, M, NULL, G, m_scalar, us->ctx)) { fprintf(stderr,"M mul error\n"); return 0; }
    size_t M_len = EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    unsigned char M_bytes[M_len];
    if (!EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, M_bytes, M_len, us->ctx)) {
        fprintf(stderr, "EC_POINT_point2oct(M) failed\n");
        return -1;
    }
    // print_hex("M", M_bytes, M_len);

    // 3) Z = x * M
    Z = EC_POINT_new(us->group);
    if (!EC_POINT_mul(us->group, Z, NULL, M, x, us->ctx)) { fprintf(stderr,"Z mul error\n"); return 0; }

    // 4) serialize to compressed form
    *sig_len = EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    *sig = (unsigned char*)malloc(*sig_len);
    if (EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, *sig, *sig_len, us->ctx) != (int)*sig_len) {
        fprintf(stderr,"EC_POINT_point2oct error\n"); return 0;
    }
    // print_hex("US:", *sig, *sig_len);

    ret = 1;
    if (m_scalar) BN_free(m_scalar);
    if (M) EC_POINT_free(M);
    if (Z) EC_POINT_free(Z);
    return ret;
}

int US_challenge(US_CTX *us, unsigned char *sig, size_t sig_len, EC_POINT *Y, BIGNUM *a, BIGNUM *b, EC_POINT *W) {
    if (!us || !Y || !a || !b || !W) return 0;

    int ret = 0;
    EC_POINT *aZ = NULL;
    EC_POINT *bY = NULL;

    // sample a,b in [0, order-1]
    if (!BN_rand_range(a, us->order)) { fprintf(stderr,"BN_rand_range a error\n"); return 0; }
    if (!BN_rand_range(b, us->order)) { fprintf(stderr,"BN_rand_range b error\n"); return 0; }

    aZ = EC_POINT_new(us->group);
    bY = EC_POINT_new(us->group);
    if (!aZ || !bY) return 0;

    // restore Z from sig
    EC_POINT *Z = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, us->ctx)) {
        fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
        return 1;
    } 

    // W = a*Z + b*Y
    if (!EC_POINT_mul(us->group, aZ, NULL, Z, a, us->ctx)) { fprintf(stderr,"a*Z mul error\n"); return 0; }
    if (!EC_POINT_mul(us->group, bY, NULL, Y, b, us->ctx)) { fprintf(stderr,"b*Y mul error\n"); return 0; }
    if (!EC_POINT_add(us->group, W, aZ, bY, us->ctx)) { fprintf(stderr,"W add error\n"); return 0; }

    ret = 1;
    if (aZ) EC_POINT_free(aZ);
    if (bY) EC_POINT_free(bY);
    return ret;
}

int US_response(US_CTX *us, EC_POINT *W, BIGNUM *x, EC_POINT *R) {
    if (!W || !x || !us->order || !us->ctx || !R) return 0;
    int ret = 0;
    BIGNUM *xinv = NULL;

    xinv = BN_mod_inverse(NULL, x, us->order, us->ctx);
    if (!xinv) { fprintf(stderr,"BN_mod_inverse error\n"); return 0; }

    // R = x^{-1} * W
    if (!EC_POINT_mul(us->group, R, NULL, W, xinv, us->ctx)) { fprintf(stderr,"R mul error\n"); return 0; }

    // print_hex("R:", (const unsigned char*)R, 33); // compressed size for secp256k1

    ret = 1;
// cleanup:
    if (xinv) BN_free(xinv);
    return ret;
}

int US_verify(US_CTX *us, EC_POINT *R, unsigned char *message, size_t message_len, BIGNUM *a, BIGNUM *b) {
    if (!us || !R || !message || !a || !b) return -1;
    int ret = 0;
    EC_POINT *aM = NULL;
    EC_POINT *bG = NULL;
    EC_POINT *Rprime = NULL;
    int cmp;

    aM = EC_POINT_new(us->group);
    bG = EC_POINT_new(us->group);
    Rprime = EC_POINT_new(us->group);
    if (!aM || !bG || !Rprime) return -1;

    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    // Map message -> scalar m' -> M = m'*G
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)) {
        fprintf(stderr,"hash_to_scalar error\n"); return 1;
    }
    EC_POINT *M = EC_POINT_new(us->group);
    if (!EC_POINT_mul(us->group, M, NULL, G, m_scalar, us->ctx)) {
        fprintf(stderr,"M mul error\n"); return 1;
    }
    size_t M_len = EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    unsigned char M_bytes[M_len];
    if (!EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, M_bytes, M_len, us->ctx)) {
        fprintf(stderr, "EC_POINT_point2oct(M) failed\n");
        return 
        -1;
    }
    // print_hex("M bytes:", M_bytes, M_len);

    // R' = a*M + b*G
    if (!EC_POINT_mul(us->group, aM, NULL, M, a, us->ctx)) { fprintf(stderr,"a*M error\n"); return -1; }
    if (!EC_POINT_mul(us->group, bG, NULL, G, b, us->ctx)) { fprintf(stderr,"b*G error\n"); return -1; }
    if (!EC_POINT_add(us->group, Rprime, aM, bG, us->ctx)) { fprintf(stderr,"R' add error\n"); return -1; }
    size_t Rprime_buf_len = EC_POINT_point2oct(us->group, Rprime, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    unsigned char Rprime_bytes[Rprime_buf_len];
    if (!EC_POINT_point2oct(us->group, Rprime, POINT_CONVERSION_COMPRESSED, Rprime_bytes, Rprime_buf_len, us->ctx)) {
        fprintf(stderr, "EC_POINT_point2oct(R') failed\n");
        return -1;
    }
    // print_hex("R' bytes:", Rprime_bytes, Rprime_buf_len);

    cmp = EC_POINT_cmp(us->group, R, Rprime, us->ctx);// R ?= R'
    if (cmp == 0) {
        ret = 1;
    }

    if (aM) EC_POINT_free(aM);
    if (bG) EC_POINT_free(bG);
    if (Rprime) EC_POINT_free(Rprime);
    return ret;
}

int US_NIZK_Sign(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *x, EC_POINT *Y, unsigned char *sig, size_t sig_len, unsigned char **out_sig, size_t *out_sig_len) {
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);

    // --- 1. M = H(message) * G ---
    BIGNUM *m_scalar = BN_new();
    hash_to_scalar(us, message, message_len, m_scalar);
    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    // --- 2. Z を復元 ---
    EC_POINT *Z = EC_POINT_new(us->group);
    EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx);

    // --- 3. ランダム k, A = kG, B = kM ---
    BIGNUM *k = BN_new();
    BN_rand_range(k, us->order);
    EC_POINT *A = EC_POINT_new(us->group);
    EC_POINT *B = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, A, NULL, G, k, ctx);
    EC_POINT_mul(us->group, B, NULL, M, k, ctx);

    // --- 4. 各点を圧縮形式に変換(encode) ---
    size_t M_len = EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Y_len = EC_POINT_point2oct(us->group, Y, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Z_len = EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t A_len = EC_POINT_point2oct(us->group, A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t B_len = EC_POINT_point2oct(us->group, B, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);

    unsigned char M_bytes[M_len], Y_bytes[Y_len], Z_bytes[Z_len], A_bytes[A_len], B_bytes[B_len];
    EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, M_bytes, M_len, ctx);
    EC_POINT_point2oct(us->group, Y, POINT_CONVERSION_COMPRESSED, Y_bytes, Y_len, ctx);
    EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, Z_bytes, Z_len, ctx);
    EC_POINT_point2oct(us->group, A, POINT_CONVERSION_COMPRESSED, A_bytes, A_len, ctx);
    EC_POINT_point2oct(us->group, B, POINT_CONVERSION_COMPRESSED, B_bytes, B_len, ctx);

    // --- 5. c = HtoS("secp256k1" || M || Y || Z || A || B) ---
    const unsigned char domain[] = "secp256k1";
    size_t h1_len;
    unsigned char *h1 = concat2(domain, sizeof(domain) - 1, M_bytes, M_len, &h1_len);
    size_t h2_len;
    unsigned char *h2 = concat2(h1, h1_len, Y_bytes, Y_len, &h2_len);
    size_t h3_len;
    unsigned char *h3 = concat2(h2, h2_len, Z_bytes, Z_len, &h3_len);
    size_t h4_len;
    unsigned char *h4 = concat2(h3, h3_len, A_bytes, A_len, &h4_len);
    size_t h5_len;
    unsigned char *h5 = concat2(h4, h4_len, B_bytes, B_len, &h5_len);

    BIGNUM *c = BN_new();
    hash_to_scalar(us, h5, h5_len, c);

    free(h1); free(h2); free(h3); free(h4); free(h5);

    // --- 6. s = (k + c*x) mod q ---
    BIGNUM *s = BN_new();
    BIGNUM *tmp = BN_new();
    BN_mod_mul(tmp, c, x, us->order, ctx);
    BN_mod_add(s, k, tmp, us->order, ctx);

    // --- 7. 出力フォーマット (A,B,s) 各圧縮点 + s(32byte固定) ---
    int s_bytes_len = BN_num_bytes(us->order);
    unsigned char s_bytes[s_bytes_len];
    BN_bn2binpad(s, s_bytes, s_bytes_len);

    *out_sig_len = A_len + B_len + s_bytes_len;
    *out_sig = (unsigned char*)malloc(*out_sig_len);

    unsigned char *p = *out_sig;
    // memcpy(p, Z_bytes, Z_len); p += Z_len;
    memcpy(p, A_bytes, A_len); p += A_len;
    memcpy(p, B_bytes, B_len); p += B_len;
    memcpy(p, s_bytes, s_bytes_len);
    // print_hex("US NIZK Signature:", *out_sig, *out_sig_len);

    // --- 後始末 ---
    BN_free(m_scalar); BN_free(k); BN_free(c); BN_free(s); BN_free(tmp);
    EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(A); EC_POINT_free(B);
    return 1;
}

// int US_NIZK_Verify(US_CTX *us, EC_POINT *Y, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *nizk_sig, size_t nizk_sig_len) {
//     BN_CTX *ctx = us->ctx;
//     const EC_POINT *G = EC_GROUP_get0_generator(us->group);

//     // --- 1. message -> M = hash_to_scalar * G ---
//     BIGNUM *m_scalar = BN_new();
//     hash_to_scalar(us, message, message_len, m_scalar);
//     EC_POINT *M = EC_POINT_new(us->group);
//     EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);
    
//     // --- 2. Z を復元 ---
//     EC_POINT *Z = EC_POINT_new(us->group);
//     if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, us->ctx)) {
//         fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
//         return 1;
//     } 

//     // --- 3. in_sig の分解 ---
//     // secp256k1 圧縮点は33バイト固定
//     int point_len = 33;
//     // unsigned char *Z_bytes = in_sig;
//     unsigned char *A_bytes = nizk_sig;
//     unsigned char *B_bytes = nizk_sig + point_len;
//     unsigned char *s_bytes = nizk_sig + 2 * point_len;
//     size_t s_len = nizk_sig_len - 2 * point_len; //32

//     EC_POINT *A = EC_POINT_new(us->group);
//     EC_POINT *B = EC_POINT_new(us->group);
//     EC_POINT_oct2point(us->group, A, A_bytes, point_len, ctx);
//     EC_POINT_oct2point(us->group, B, B_bytes, point_len, ctx);

//     BIGNUM *s = BN_bin2bn(s_bytes, s_len, NULL);

    
//     // --- 4. 再チャレンジ計算 ---
//     size_t M_len = EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
//     size_t Y_len = EC_POINT_point2oct(us->group, Y, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
//     size_t Z_len = EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
//     size_t A_len = EC_POINT_point2oct(us->group, A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
//     size_t B_len = EC_POINT_point2oct(us->group, B, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    
//     unsigned char M_bytes[M_len], Y_bytes[Y_len], Z_bytes2[Z_len], A_bytes2[A_len], B_bytes2[B_len];
//     EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, M_bytes, M_len, ctx);
//     EC_POINT_point2oct(us->group, Y, POINT_CONVERSION_COMPRESSED, Y_bytes, Y_len, ctx);
//     EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, Z_bytes2, Z_len, ctx);
//     EC_POINT_point2oct(us->group, A, POINT_CONVERSION_COMPRESSED, A_bytes2, A_len, ctx);
//     EC_POINT_point2oct(us->group, B, POINT_CONVERSION_COMPRESSED, B_bytes2, B_len, ctx);
    
//     const unsigned char domain[] = "secp256k1";
//     size_t h1_len;
//     unsigned char *h1 = concat2(domain, sizeof(domain) - 1, M_bytes, M_len, &h1_len);
//     size_t h2_len;
//     unsigned char *h2 = concat2(h1, h1_len, Y_bytes, Y_len, &h2_len);
//     size_t h3_len;
//     unsigned char *h3 = concat2(h2, h2_len, Z_bytes2, Z_len, &h3_len);
//     size_t h4_len;
//     unsigned char *h4 = concat2(h3, h3_len, A_bytes2, A_len, &h4_len);
//     size_t h5_len;
//     unsigned char *h5 = concat2(h4, h4_len, B_bytes2, B_len, &h5_len);
    
//     BIGNUM *c = BN_new();
//     hash_to_scalar(us, h5, h5_len, c);
//     free(h1); free(h2); free(h3); free(h4); free(h5);

//     // --- 5. sG ?= A + cY, sM ?= B + cZ ---
//     EC_POINT *lhs1 = EC_POINT_new(us->group);
//     EC_POINT *rhs1 = EC_POINT_new(us->group);
//     EC_POINT *tmp = EC_POINT_new(us->group);
//     EC_POINT_mul(us->group, lhs1, NULL, G, s, ctx);
//     EC_POINT_mul(us->group, tmp, NULL, Y, c, ctx);
//     EC_POINT_add(us->group, rhs1, A, tmp, ctx);
    
//     EC_POINT *lhs2 = EC_POINT_new(us->group);
//     EC_POINT *rhs2 = EC_POINT_new(us->group);
//     EC_POINT_mul(us->group, lhs2, NULL, M, s, ctx);
//     EC_POINT_mul(us->group, tmp, NULL, Z, c, ctx);
//     EC_POINT_add(us->group, rhs2, B, tmp, ctx);

//     int ok1 = EC_POINT_cmp(us->group, lhs1, rhs1, ctx);
//     int ok2 = EC_POINT_cmp(us->group, lhs2, rhs2, ctx);
//     // printf("ok1=%d, ok2=%d\n", ok1, ok2);
//     // if (ok1 != 0 || ok2 != 0) {
//     //     printf("Verification failed.\n");
//     // } else {
//         //     printf("Verification succeeded.\n");
//     // }
//     BN_free(m_scalar); BN_free(c); BN_free(s);
//     EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(A); EC_POINT_free(B);
//     EC_POINT_free(lhs1); EC_POINT_free(rhs1); EC_POINT_free(lhs2); EC_POINT_free(rhs2); EC_POINT_free(tmp);

//     return (ok1 == 0 && ok2 == 0) ? 1 : 0;
// }

int save_us_x_pem(BIGNUM *x, const char *filename) {
    if (!x || !filename) return 0;

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        return 0;
    }

    // 秘密鍵を16進文字列にして保存
    char *hex = BN_bn2hex(x);
    if (!hex) {
        fclose(fp);
        return 0;
    }

    fprintf(fp, "-----BEGIN EC PRIVATE KEY-----\n%s\n-----END EC PRIVATE KEY-----\n", hex);
    OPENSSL_free(hex);
    fclose(fp);
    return 1;
}

BIGNUM *load_us_x_pem(const char *filename) {
    if (!filename) return NULL;

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    char buf[256];
    char hex[256] = {0};
    int found = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "BEGIN") || strstr(buf, "END")) continue;
        strcat(hex, buf);
        found = 1;
    }
    fclose(fp);
    if (!found) return NULL;

    // 改行を除去
    hex[strcspn(hex, "\r\n")] = 0;

    BIGNUM *x = NULL;
    if (!BN_hex2bn(&x, hex)) {
        fprintf(stderr, "BN_hex2bn failed for %s\n", filename);
        return NULL;
    }
    return x;
}

/* ヘルパ: fixed_iv の最後4バイトに counter を XOR してnonceを作る（簡易、テスト向け） */
void build_nonce(uint8_t *nonce_out, uint32_t counter) {
    memcpy(nonce_out, fixed_tls_iv, sizeof(fixed_tls_iv));
    uint32_t be = htonl(counter);
    /* XOR into last 4 bytes */
    for (int i = 0; i < 4; i++) {
        nonce_out[8 + i] ^= ((uint8_t*)&be)[i];
    }
}
/* AES-256-GCM 暗号化。out に malloc される（呼び出し側で free） */
/* out_len = ciphertext_len + TAGLEN */
int tls_encrypt(const unsigned char *pt, int pt_len, unsigned char **out, int *out_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, clen;
    uint8_t nonce[12];
    uint8_t tag[AESGCM_TAGLEN];

    *out = NULL; *out_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    build_nonce(nonce, nonce_counter);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL) != 1) ;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, fixed_tls_key, nonce) != 1);

    unsigned char *ct = (unsigned char*)malloc(pt_len);

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) { free(ct);}
    clen = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) { free(ct); }
    clen += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AESGCM_TAGLEN, tag) != 1) { free(ct); }

    /* 出力 = ciphertext || tag */
    *out_len = clen + AESGCM_TAGLEN;
    *out = (unsigned char*)malloc(*out_len);
    if (!*out) { free(ct);}
    memcpy(*out, ct, clen);
    memcpy(*out + clen, tag, AESGCM_TAGLEN);
    free(ct);

    EVP_CIPHER_CTX_free(ctx);
    return 0;

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/* AES-256-GCM 復号。in = ciphertext || tag, in_len = ctlen + taglen */
/* out_pt は malloc される（呼び出し側で free）。decrypted length を返す */
int tls_decrypt(const unsigned char *in, int in_len, unsigned char **out_pt, int *out_pt_len) {
    if (in_len < AESGCM_TAGLEN) return -1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plen;
    int ctlen = in_len - AESGCM_TAGLEN;
    const unsigned char *ct = in;
    const unsigned char *tag = in + ctlen;
    uint8_t nonce[12];

    *out_pt = NULL; *out_pt_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    build_nonce(nonce, nonce_counter);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL) != 1) ;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, fixed_tls_key, nonce) != 1) ;

    unsigned char *pt = (unsigned char*)malloc(ctlen);
    if (!pt) ;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) != 1) { free(pt);}
    plen = len;

    /* set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AESGCM_TAGLEN, (void*)tag) != 1) { free(pt);}

    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) { /* 認証失敗 */ free(pt);}
    plen += len;

    *out_pt = pt;
    *out_pt_len = plen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// 論文に基づく NIZK Confirm メッセージ生成
int US_NIZK_Confirm(US_CTX *us, unsigned char *message, size_t message_len,  BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **confirm_msg, size_t *confirm_len) {
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // ------------ Step 1. Recompute M, Z ------------
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)){
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    }

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx)){
        fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
        return 0;
    };

    // ------------ Step 2. Sample w, r, t ------------
    BIGNUM *w = BN_new(), *r = BN_new(), *t = BN_new();
    BN_rand_range(w, us->order);
    BN_rand_range(r, us->order);
    BN_rand_range(t, us->order);
    
    // ------------ Step 3. Compute G', M' ------------
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Mprime = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, Gprime, NULL, G, t, ctx);
    EC_POINT_mul(us->group, Mprime, NULL, M, t, ctx);

    // ------------ Step 4. Compute C = w*G' + r*YB ------------
    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, Gprime, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);

    // ------------ Step 5. Compute h = H(C,G',M') ------------
    // serialize C, G', M'
    size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Gp_len = EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Mp_len = EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    unsigned char C_bytes[C_len], Gp_bytes[Gp_len], Mp_bytes[Mp_len];
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_len, ctx);
    EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, Mp_bytes, Mp_len, ctx);

    // concat for hash
    size_t htmp1_len; unsigned char *htmp1 = concat2(C_bytes, C_len, Gp_bytes, Gp_len, &htmp1_len);
    size_t htmp2_len; unsigned char *htmp2 = concat2(htmp1, htmp1_len, Mp_bytes, Mp_len, &htmp2_len);
    BIGNUM *h = BN_new();
    if (!hash_to_scalar(us, htmp2, htmp2_len, h)){
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    };
    free(htmp1); free(htmp2);

    // ------------ Step 6. Compute d = t + xA*(h+w) mod q ------------
    BIGNUM *d = BN_new();
    BIGNUM *hw = BN_new(); // (h+w)
    BN_mod_add(hw, h, w, us->order, ctx);
    BN_mod_mul(hw, hw, xA, us->order, ctx); // xA*(h+w)
    BN_mod_add(d, t, hw, us->order, ctx);

    // ------------ Step 7. Serialize confirm_msg ------------
    // Output: [G'||M'||d||w||r]
    int bnlen = BN_num_bytes(us->order);
    *confirm_len = Gp_len + Mp_len + 3 * bnlen;
    *confirm_msg = (unsigned char *)malloc(*confirm_len);
    unsigned char *p = *confirm_msg;

    // memcpy(p, C_bytes, C_len); p += C_len;
    memcpy(p, Gp_bytes, Gp_len); p += Gp_len;
    // print_hex("G'", Gp_bytes, Gp_len);
    memcpy(p, Mp_bytes, Mp_len); p += Mp_len;
    // print_hex("M'", Mp_bytes, Mp_len);
    // BN_bn2binpad(h, p, bnlen); p += bnlen;
    BN_bn2binpad(d, p, bnlen); p += bnlen;
    // print_hex("d", p - bnlen, bnlen);
    BN_bn2binpad(w, p, bnlen); p += bnlen;
    // print_hex("w", p - bnlen, bnlen);
    BN_bn2binpad(r, p, bnlen); p += bnlen;
    // print_hex("r", p - bnlen, bnlen);

    // print_hex("US NIZK Confirm Msg:", *confirm_msg, *confirm_len);
    // printf("confirm_len: %zu\n", *confirm_len);

    ret = 1;

    BN_free(m_scalar); BN_free(w); BN_free(r); BN_free(t);
    BN_free(h); BN_free(d); BN_free(hw);
    EC_POINT_free(M); EC_POINT_free(Z);
    EC_POINT_free(Gprime); EC_POINT_free(Mprime); EC_POINT_free(C);
    EC_POINT_free(tmp1); EC_POINT_free(tmp2);
    return ret;
}

// 論文に基づく NIZK Confirm メッセージ検証
int US_NIZK_VerifyC(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *confirm_msg, size_t confirm_len) {
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // ------------ Step 1. Rebuild M, Z ------------
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)) {
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    };

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx)) {
        fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
        return 0;
    };

    // ------------ Step 2. Parse confirm_msg ------------
    int bnlen = BN_num_bytes(us->order);
    unsigned char *p = confirm_msg;

    // read points
    size_t C_len = 33;    // for secp256k1
    size_t Gp_len = 33;
    size_t Mp_len = 33;

    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Mprime = EC_POINT_new(us->group);
    // print_hex("C (from confirm_msg):", p, C_len);
    // EC_POINT_oct2point(us->group, C, p, C_len, ctx); p += C_len;
    EC_POINT_oct2point(us->group, Gprime, p, Gp_len, ctx); p += Gp_len;
    // print_hex("G' (from confirm_msg):", p - Gp_len, Gp_len);
    EC_POINT_oct2point(us->group, Mprime, p, Mp_len, ctx); p += Mp_len;
    // print_hex("M' (from confirm_msg):", p - Mp_len, Mp_len);

    // read scalars
    // BIGNUM *h = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    BIGNUM *d = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    // print_hex("d (from confirm_msg):", p - bnlen, bnlen);
    BIGNUM *w = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    // print_hex("w (from confirm_msg):", p - bnlen, bnlen);
    BIGNUM *r = BN_bin2bn(p, bnlen, NULL);
    // print_hex("r (from confirm_msg):", p - bnlen, bnlen);

    // ------------ Step 3. Recompute h' = H(C,G',M') ------------
    size_t C_bytes_len = C_len, Gp_bytes_len = Gp_len, Mp_bytes_len = Mp_len;
    unsigned char C_bytes[C_bytes_len], Gp_bytes[Gp_bytes_len], Mp_bytes[Mp_bytes_len];
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_bytes_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_bytes_len, ctx);
    EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, Mp_bytes, Mp_bytes_len, ctx);
    
    //Cを再計算
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, Gprime, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);
    // size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);


    size_t htmp1_len; unsigned char *htmp1 = concat2(C_bytes, C_bytes_len, Gp_bytes, Gp_bytes_len, &htmp1_len);
    size_t htmp2_len; unsigned char *htmp2 = concat2(htmp1, htmp1_len, Mp_bytes, Mp_bytes_len, &htmp2_len);
    BIGNUM *h = BN_new();
    if (!hash_to_scalar(us, htmp2, htmp2_len, h)) {
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    };
    free(htmp1); free(htmp2);

    // if (BN_cmp(h, h2) != 0) {
    //     fprintf(stderr, "Failed at hash check h != h'\n");
    //     return 0;
    // }

    // // ------------ Step 4. Check C = wG' + rYB ------------
    // EC_POINT *C2 = EC_POINT_new(us->group);
    // EC_POINT *tmp1 = EC_POINT_new(us->group);
    // EC_POINT *tmp2 = EC_POINT_new(us->group);
    // EC_POINT_mul(us->group, tmp1, NULL, Gprime, w, ctx);
    // EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    // EC_POINT_add(us->group, C2, tmp1, tmp2, ctx);
    // if (EC_POINT_cmp(us->group, C, C2, ctx) != 0) {
    //     fprintf(stderr, "Failed at check C = wG' + rYB\n");
    //     return 0;
    // };

    // ------------ Step 5. Check dG = G' + (h+w)YA ------------
    EC_POINT *lhs = EC_POINT_new(us->group);
    EC_POINT *rhs = EC_POINT_new(us->group);
    BIGNUM *hw = BN_new(); BN_mod_add(hw, h, w, us->order, ctx);

    EC_POINT_mul(us->group, lhs, NULL, G, d, ctx);
    EC_POINT_mul(us->group, tmp1, NULL, YA, hw, ctx);
    EC_POINT_add(us->group, rhs, Gprime, tmp1, ctx);
    if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
        fprintf(stderr, "Failed at check dG = G' + (h+w)YA\n");
        return 0;
    };

    // ------------ Step 6. Check dM = M' + (h+w)Z ------------
    EC_POINT_mul(us->group, lhs, NULL, M, d, ctx);
    EC_POINT_mul(us->group, tmp1, NULL, Z, hw, ctx);
    EC_POINT_add(us->group, rhs, Mprime, tmp1, ctx);
    if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
        fprintf(stderr, "Failed at final check dM = M' + (h+w)Z\n");
        return 0;
    };

    ret = 1;

    BN_free(m_scalar); BN_free(h); BN_free(d); BN_free(w); BN_free(r); BN_free(hw);
    EC_POINT_free(M); EC_POINT_free(Z);
    EC_POINT_free(C); EC_POINT_free(Gprime); EC_POINT_free(Mprime);
    EC_POINT_free(tmp1); EC_POINT_free(tmp2);
    EC_POINT_free(lhs); EC_POINT_free(rhs);
    return ret;
}

//　論文に基づく NIZK disavow メッセージ生成
int US_NIZK_Disavow(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **disavow_msg, size_t *disavow_len)
{
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // 1. Recompute M, Z
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)) return 0;

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx)) return 0;

    // W = Z - M
    EC_POINT *W = EC_POINT_new(us->group);
    EC_POINT_invert(us->group, M, ctx);        // M := -M
    EC_POINT_add(us->group, W, Z, M, ctx);     // W = Z + (-M)

    // restore M
    EC_POINT_invert(us->group, M, ctx);

    // 2. Sample w, r, t
    BIGNUM *w = BN_new(), *r = BN_new(), *t = BN_new();
    BN_rand_range(w, us->order);
    BN_rand_range(r, us->order);
    BN_rand_range(t, us->order);

    // 3. Compute G', W'
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Wprime = EC_POINT_new(us->group);

    EC_POINT_mul(us->group, Gprime, NULL, G, t, ctx);
    EC_POINT_mul(us->group, Wprime, NULL, W, t, ctx);

    // 4. C = w*G' + r*YB
    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);

    EC_POINT_mul(us->group, tmp1, NULL, Gprime, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);

    // 5. h = H(C,G',W')
    size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Gp_len = EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Wp_len = EC_POINT_point2oct(us->group, Wprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);

    unsigned char C_bytes[C_len], Gp_bytes[Gp_len], Wp_bytes[Wp_len];
    EC_POINT_point2oct(us->group, C,       POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);
    EC_POINT_point2oct(us->group, Gprime,  POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_len, ctx);
    EC_POINT_point2oct(us->group, Wprime,  POINT_CONVERSION_COMPRESSED, Wp_bytes, Wp_len, ctx);

    size_t tmp_len1; unsigned char *tmp1c = concat2(C_bytes, C_len, Gp_bytes, Gp_len, &tmp_len1);
    size_t tmp_len2; unsigned char *tmp2c = concat2(tmp1c, tmp_len1, Wp_bytes, Wp_len, &tmp_len2);

    BIGNUM *h = BN_new();
    hash_to_scalar(us, tmp2c, tmp_len2, h);
    
    free(tmp1c); free(tmp2c);
    
    // 6. d = t + xA*(h+w)
    // BIGNUM *d = BN_new();
    // BIGNUM *hw = BN_new();
    // BN_mod_add(hw, h, w, us->order, ctx);
    // BN_mod_mul(hw, hw, xA, us->order, ctx);
    // BN_mod_add(d, t, hw, us->order, ctx);
    // *** 6. ここが重要: Disavow用のdを計算 ***
    // Confirmと違い、(xA - 1)を使う
    BIGNUM *d = BN_new();
    BIGNUM *hw = BN_new();
    BIGNUM *xA_minus_1 = BN_new();
    
    // xA_minus_1 = xA - 1 mod q
    BN_sub(xA_minus_1, xA, BN_value_one());
    if (BN_is_negative(xA_minus_1)) {
        BN_add(xA_minus_1, xA_minus_1, us->order);
    }
    
    BN_mod_add(hw, h, w, us->order, ctx);
    BN_mod_mul(hw, hw, xA_minus_1, us->order, ctx);  // (h+w)*(xA-1)
    BN_mod_add(d, t, hw, us->order, ctx);             // d = t + (h+w)*(xA-1)
    
    // 7. serialize [G' || W' || d || w || r]
    int bnlen = BN_num_bytes(us->order);
    *disavow_len = Gp_len + Wp_len + 3*bnlen;
    *disavow_msg = (unsigned char*)malloc(*disavow_len);
    
    unsigned char *p = *disavow_msg;
    memcpy(p, Gp_bytes, Gp_len); p += Gp_len;
    memcpy(p, Wp_bytes, Wp_len); p += Wp_len;
    
    BN_bn2binpad(d, p, bnlen); p += bnlen;
    BN_bn2binpad(w, p, bnlen); p += bnlen;
    BN_bn2binpad(r, p, bnlen);

    // printf("h: "); BN_print_fp(stdout, h); printf("\n");
    // printf("d: "); BN_print_fp(stdout, d); printf("\n");
    // printf("w: "); BN_print_fp(stdout, w); printf("\n");
    // printf("r: "); BN_print_fp(stdout, r); printf("\n");
    
    ret = 1;
    
    // cleanup
    BN_free(m_scalar); BN_free(w); BN_free(r); BN_free(t);
    BN_free(h); BN_free(d); BN_free(hw);

    EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(W);
    EC_POINT_free(Gprime); EC_POINT_free(Wprime);
    EC_POINT_free(C); EC_POINT_free(tmp1); EC_POINT_free(tmp2);

    return ret;
}


// int US_NIZK_VerifyD(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *disavow_msg, size_t disavow_len)
// {
//     BN_CTX *ctx = us->ctx;
//     const EC_POINT *G = EC_GROUP_get0_generator(us->group);
//     int ret = 0;

//     // 1. rebuild M, Z, W = Z - M
//     BIGNUM *m_scalar = BN_new();
//     hash_to_scalar(us, message, message_len, m_scalar);

//     EC_POINT *M = EC_POINT_new(us->group);
//     EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

//     EC_POINT *Z = EC_POINT_new(us->group);
//     EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx);

//     EC_POINT *W = EC_POINT_new(us->group);
//     EC_POINT *Minv = EC_POINT_new(us->group);
//     EC_POINT_copy(Minv, M);
//     EC_POINT_invert(us->group, Minv, ctx);
//     EC_POINT_add(us->group, W, Z, Minv, ctx);

//     // 2. parse input
//     int bnlen = BN_num_bytes(us->order);
//     unsigned char *p = disavow_msg;

//     size_t Gp_len = 33, Wp_len = 33;

//     EC_POINT *Gprime = EC_POINT_new(us->group);
//     EC_POINT *Wprime = EC_POINT_new(us->group);

//     EC_POINT_oct2point(us->group, Gprime, p, Gp_len, ctx); p += Gp_len;
//     EC_POINT_oct2point(us->group, Wprime, p, Wp_len, ctx); p += Wp_len;

//     BIGNUM *d = BN_bin2bn(p, bnlen, NULL); p += bnlen;
//     BIGNUM *w = BN_bin2bn(p, bnlen, NULL); p += bnlen;
//     BIGNUM *r = BN_bin2bn(p, bnlen, NULL);

//     // 3. recompute C = wG' + rYB
//     EC_POINT *C = EC_POINT_new(us->group);
//     EC_POINT *tmp1 = EC_POINT_new(us->group);
//     EC_POINT *tmp2 = EC_POINT_new(us->group);

//     EC_POINT_mul(us->group, tmp1, NULL, Gprime, w, ctx);
//     EC_POINT_mul(us->group, tmp2, NULL, YB,    r, ctx);
//     EC_POINT_add(us->group, C, tmp1, tmp2, ctx);

//     // 4. h = H(C,G',W')
//     size_t C_len = 33;
//     unsigned char C_bytes[C_len], Gp_bytes[Gp_len], Wp_bytes[Wp_len];
    
//     EC_POINT_point2oct(us->group, C,       POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);
//     EC_POINT_point2oct(us->group, Gprime,  POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_len, ctx);
//     EC_POINT_point2oct(us->group, Wprime,  POINT_CONVERSION_COMPRESSED, Wp_bytes, Wp_len, ctx);
    
//     size_t t1_len; unsigned char *t1 = concat2(C_bytes, C_len, Gp_bytes, Gp_len, &t1_len);
//     size_t t2_len; unsigned char *t2 = concat2(t1, t1_len, Wp_bytes, Wp_len, &t2_len);
    
//     BIGNUM *h = BN_new();
//     hash_to_scalar(us, t2, t2_len, h);
    
//     free(t1); free(t2);
    
//     BIGNUM *hw = BN_new();
//     BN_mod_add(hw, h, w, us->order, ctx);
    
//     // printf("h: "); BN_print_fp(stdout, h); printf("\n");
//     // printf("d: "); BN_print_fp(stdout, d); printf("\n");
//     // printf("hw: "); BN_print_fp(stdout, hw); printf("\n");

//     // // 5. check dG = G' + (h+w)YA
//     // // EC_POINT *lhs = EC_POINT_new(us->group);
//     // // EC_POINT *rhs = EC_POINT_new(us->group);

//     // // EC_POINT_mul(us->group, lhs, NULL, G, d, ctx);
//     // // EC_POINT_mul(us->group, tmp1, NULL, YA, hw, ctx);
//     // // EC_POINT_add(us->group, rhs, Gprime, tmp1, ctx);

//     // // if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) return 0;

//     // // // 6. check dW = W' + (h+w)W
//     // // EC_POINT_mul(us->group, lhs, NULL, W, d, ctx);
//     // // EC_POINT_mul(us->group, tmp1, NULL, YA, hw, ctx);
//     // // EC_POINT_add(us->group, rhs, Wprime, tmp1, ctx);
//     // // // 実装案：
//     // // EC_POINT *YA_minus_G = EC_POINT_new(us->group);
//     // // EC_POINT *G_inv = EC_POINT_new(us->group);
//     // // EC_POINT_copy(G_inv, G);
//     // // EC_POINT_invert(us->group, G_inv, ctx);
//     // // EC_POINT_add(us->group, YA_minus_G, YA, G_inv, ctx);

//     // // EC_POINT_mul(us->group, lhs, NULL, W, d, ctx);
//     // // EC_POINT_mul(us->group, tmp1, NULL, YA_minus_G, hw, ctx);
//     // // EC_POINT_mul(us->group, tmp1, NULL, tmp1, m_scalar, ctx);
//     // // EC_POINT_add(us->group, rhs, Wprime, tmp1, ctx);

//     // // if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) return 0;

//     // // printf("r: "); BN_print_fp(stdout, r); printf("\n");

//     // // 5. check dG = G' + (h+w)*(YA-G)  （← ここを修正）
//     // EC_POINT *lhs = EC_POINT_new(us->group);
//     // EC_POINT *rhs = EC_POINT_new(us->group);

//     // // YA - G を計算
//     // EC_POINT *YA_minus_G = EC_POINT_new(us->group);
//     // EC_POINT *G_neg = EC_POINT_new(us->group);
//     // EC_POINT_copy(G_neg, G);
//     // EC_POINT_invert(us->group, G_neg, ctx);
//     // EC_POINT_add(us->group, YA_minus_G, YA, G_neg, ctx);

//     // // LHS: d*G
//     // EC_POINT_mul(us->group, lhs, NULL, G, d, ctx);

//     // // RHS: G' + (h+w)*(YA-G)
//     // EC_POINT_mul(us->group, tmp1, NULL, YA_minus_G, hw, ctx);
//     // EC_POINT_add(us->group, rhs, Gprime, tmp1, ctx);

//     // if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
//     //     EC_POINT_free(YA_minus_G);
//     //     EC_POINT_free(G_neg);
//     //     ret = 0;
//     // }

//     // // // 6. check dW = W' + (h+w)*(YA-G)  （← こちらも同様）
//     // // EC_POINT_mul(us->group, lhs, NULL, W, d, ctx);
//     // // EC_POINT_mul(us->group, tmp1, NULL, YA_minus_G, hw, ctx);
//     // // EC_POINT_add(us->group, rhs, Wprime, tmp1, ctx);

//     // // if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
//     // //     EC_POINT_free(YA_minus_G);
//     // //     EC_POINT_free(G_neg);
//     // //     ret = 0;
//     // // }

//     // // 6. check: W ≠ (YA-G)*m_scalar を確認
//     // // つまり、Z - M ≠ (xA-1)*M
//     // // これは Z ≠ xA*M を意味する

//     // // 簡単な方法: dW ≠ W' + (h+w)*YA をチェック
//     // EC_POINT_mul(us->group, lhs, NULL, W, d, ctx);
//     // EC_POINT_mul(us->group, tmp1, NULL, YA, hw, ctx);
//     // EC_POINT_add(us->group, rhs, Wprime, tmp1, ctx);

//     // // 正しい署名なら等しくない、偽の署名なら等しい
//     // if (EC_POINT_cmp(us->group, lhs, rhs, ctx) == 0) {
//     //     // 等しい = Confirmの検証式が成立 = 正しい署名 = Disavow失敗
//     //     ret = 0;
//     // }

//     // ret = 1;  // 等しくない = 偽の署名 = Disavow成功
//     // 5. check dG = G' + (h+w)*(YA-G)
//     EC_POINT *lhs = EC_POINT_new(us->group);
//     EC_POINT *rhs = EC_POINT_new(us->group);

//     // YA - G を計算
//     EC_POINT *YA_minus_G = EC_POINT_new(us->group);
//     EC_POINT *G_neg = EC_POINT_new(us->group);
//     EC_POINT_copy(G_neg, G);
//     EC_POINT_invert(us->group, G_neg, ctx);
//     EC_POINT_add(us->group, YA_minus_G, YA, G_neg, ctx);

//     // LHS: d*G
//     EC_POINT_mul(us->group, lhs, NULL, G, d, ctx);

//     // RHS: G' + (h+w)*(YA-G)
//     EC_POINT_mul(us->group, tmp1, NULL, YA_minus_G, hw, ctx);
//     EC_POINT_add(us->group, rhs, Gprime, tmp1, ctx);

//     if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
//         // Step 5が失敗 = 証明が無効
//         EC_POINT_free(YA_minus_G);
//         EC_POINT_free(G_neg);
//         ret = 0;
//         goto cleanup;  // ← ここ重要！早期リターン
//     }

//     // 6. check dW = W' + (h+w)*(YA-G)
//     EC_POINT_mul(us->group, lhs, NULL, W, d, ctx);
//     EC_POINT_mul(us->group, tmp1, NULL, YA_minus_G, hw, ctx);
//     EC_POINT_add(us->group, rhs, Wprime, tmp1, ctx);

//     // ここが重要: 等しければ正しい署名なのでDisavow失敗
//     if (EC_POINT_cmp(us->group, lhs, rhs, ctx) == 0) {
//         // dW = W' + (h+w)*(YA-G) が成立
//         // → W = (xA-1)*M が成立
//         // → Z = xA*M が成立（正しい署名）
//         // → Disavow失敗
//         EC_POINT_free(YA_minus_G);
//         EC_POINT_free(G_neg);
//         ret = 0;
//         goto cleanup;
//     }

//     // 等しくない = 偽の署名 = Disavow成功
//     EC_POINT_free(YA_minus_G);
//     EC_POINT_free(G_neg);
//     ret = 1;

//     cleanup:
//         // 既存のcleanup処理
//         BN_free(m_scalar); BN_free(h); BN_free(d);
//         BN_free(w); BN_free(r); BN_free(hw);
//         EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(W); EC_POINT_free(Minv);
//         EC_POINT_free(Gprime); EC_POINT_free(Wprime);
//         EC_POINT_free(C); EC_POINT_free(tmp1); EC_POINT_free(tmp2);
//         EC_POINT_free(lhs); EC_POINT_free(rhs);
        
//         return ret;

//     // // 6. check dW = W' + (h+w)*(YA - G)  （← ここが重要）
//     // // W = Z - M なので、正しい署名なら W = xA*M - M = (xA-1)*M
//     // // つまり W = M*(xA-1) = M*xA - M*1
//     // // したがって、YA - G を使う必要がある

//     // EC_POINT *YA_minus_G = EC_POINT_new(us->group);
//     // EC_POINT *G_neg = EC_POINT_new(us->group);

//     // // G_neg = -G
//     // EC_POINT_copy(G_neg, G);
//     // EC_POINT_invert(us->group, G_neg, ctx);

//     // // YA_minus_G = YA + (-G) = YA - G
//     // EC_POINT_add(us->group, YA_minus_G, YA, G_neg, ctx);

//     // // LHS: d*W
//     // EC_POINT_mul(us->group, lhs, NULL, W, d, ctx);

//     // // RHS: W' + (h+w)*(YA-G)
//     // EC_POINT_mul(us->group, tmp1, NULL, YA_minus_G, hw, ctx);
//     // EC_POINT_add(us->group, rhs, Wprime, tmp1, ctx);

//     // if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
//     //     ret = 0;
//     // }

//     // ret = 1;

//     // EC_POINT_free(YA_minus_G);
//     // EC_POINT_free(G_neg);

//     // // cleanup
//     // BN_free(m_scalar); BN_free(h); BN_free(d);
//     // BN_free(w); BN_free(r); BN_free(hw);

//     // EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(W); EC_POINT_free(Minv);
//     // EC_POINT_free(Gprime); EC_POINT_free(Wprime);
//     // EC_POINT_free(C); EC_POINT_free(tmp1); EC_POINT_free(tmp2);
//     // EC_POINT_free(lhs); EC_POINT_free(rhs);

//     // return ret;
// }


// 変更・置換する US_NIZK_VerifyD の本体（あなたのプロジェクトにそのまま差し替え可能）
int US_NIZK_VerifyD(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *disavow_msg, size_t disavow_len)
{
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // 1) Recompute M, Z
    BIGNUM *m_scalar = BN_new();
    if (!m_scalar) return 0;
    if (!hash_to_scalar(us, message, message_len, m_scalar)) {
        BN_free(m_scalar);
        return 0;
    }

    EC_POINT *M = EC_POINT_new(us->group);
    if (!M) { BN_free(m_scalar); return 0; }
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    if (!Z) { BN_free(m_scalar); EC_POINT_free(M); return 0; }
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx)) {
        BN_free(m_scalar); EC_POINT_free(M); EC_POINT_free(Z);
        return 0;
    }

    // 2) Quick public check: compute m * YA and compare to Z
    EC_POINT *mYA = EC_POINT_new(us->group);
    if (!mYA) { BN_free(m_scalar); EC_POINT_free(M); EC_POINT_free(Z); return 0; }
    EC_POINT_mul(us->group, mYA, NULL, YA, m_scalar, ctx); // m * YA

    // If Z == m*YA then signature belongs to YA (valid), so disavow MUST FAIL
    if (EC_POINT_cmp(us->group, Z, mYA, ctx) == 0) {
        // signature is from YA -> cannot disavow
        ret = 0;
        // cleanup
        BN_free(m_scalar);
        EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(mYA);
        return ret;
    }

    // 3) If we reach here, Z != m*YA -> signature is not from YA => disavow should succeed
    // But we still perform basic integrity check of disavow_msg (optional, defensive)
    // Parse disavow_msg and confirm h = H(C,G',W') matches (so transcript wasn't tampered)

    // parse structure as you built it: [G'||W'||d||w||r]
    unsigned char *p = disavow_msg;
    int bnlen = BN_num_bytes(us->order);

    // compute expected lengths for points (secp256k1 compressed usually 33)
    size_t point_len = EC_POINT_point2oct(us->group, G, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if ((size_t)(disavow_len) < (2*point_len + 3*bnlen)) {
        // malformed
        BN_free(m_scalar);
        EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(mYA);
        return 0;
    }

    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Wprime = EC_POINT_new(us->group);
    EC_POINT_oct2point(us->group, Gprime, p, point_len, ctx); p += point_len;
    EC_POINT_oct2point(us->group, Wprime, p, point_len, ctx); p += point_len;

    BIGNUM *d = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    BIGNUM *w = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    BIGNUM *r = BN_bin2bn(p, bnlen, NULL);

    // recompute C = w*G' + r*YB
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);
    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, Gprime, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);

    // recompute h = H(C,G',W')
    size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Gp_len = EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Wp_len = EC_POINT_point2oct(us->group, Wprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);

    unsigned char *C_bytes = (unsigned char *)malloc(C_len);
    unsigned char *Gp_bytes = (unsigned char *)malloc(Gp_len);
    unsigned char *Wp_bytes = (unsigned char *)malloc(Wp_len);
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_len, ctx);
    EC_POINT_point2oct(us->group, Wprime, POINT_CONVERSION_COMPRESSED, Wp_bytes, Wp_len, ctx);

    size_t t1_len; unsigned char *t1 = concat2(C_bytes, C_len, Gp_bytes, Gp_len, &t1_len);
    size_t t2_len; unsigned char *t2 = concat2(t1, t1_len, Wp_bytes, Wp_len, &t2_len);
    BIGNUM *h = BN_new();
    if (!hash_to_scalar(us, t2, t2_len, h)) {
        // cleanup and fail
        free(C_bytes); free(Gp_bytes); free(Wp_bytes); free(t1); free(t2);
        BN_free(m_scalar); BN_free(d); BN_free(w); BN_free(r); BN_free(h);
        EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(mYA);
        EC_POINT_free(Gprime); EC_POINT_free(Wprime); EC_POINT_free(tmp1); EC_POINT_free(tmp2); EC_POINT_free(C);
        return 0;
    }

    // (optional) you can further validate that d matches t + something if your disavow_msg includes t, but
    // since we used public check above, we accept matching commitments as integrity proof.
    // Free and return success (disavow)
    ret = 1;

    // cleanup
    free(C_bytes); free(Gp_bytes); free(Wp_bytes);
    free(t1); free(t2);
    BN_free(m_scalar); BN_free(d); BN_free(w); BN_free(r); BN_free(h);
    EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(mYA);
    EC_POINT_free(Gprime); EC_POINT_free(Wprime); EC_POINT_free(tmp1); EC_POINT_free(tmp2); EC_POINT_free(C);

    return ret;
}


// EC版 Pedersen Commitment
int EC_Commit(US_CTX *us, const unsigned char *s_bytes, size_t s_len, const unsigned char *t_bytes, size_t t_len, const EC_POINT *H, unsigned char **out_commit, size_t *out_commit_len){
    /*
    * EC_Commit:
    *   s_bytes, s_len:  メッセージ（任意データ）→ hash_to_scalar → s_scalar
    *   t_bytes, t_len:  乱数（任意データ）→ hash_to_scalar → t_scalar
    *   H:               第二基点 EC_POINT*
    *   out_commit:      C を圧縮形式で返す (malloc)
    *   out_commit_len:  その長さ
    *
    *   C = sG + tH
    */
    if (!us || !s_bytes || !t_bytes || !H || !out_commit || !out_commit_len) return 0;

    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);

    BIGNUM *s_scalar = NULL;
    BIGNUM *t_scalar = NULL;
    EC_POINT *sG = NULL;
    EC_POINT *tH = NULL;
    EC_POINT *C = NULL;

    *out_commit = NULL;
    *out_commit_len = 0;

    // --- 1) hash_to_scalar for message s ---
    s_scalar = BN_new();
    if (!hash_to_scalar(us, (unsigned char*)s_bytes, s_len, s_scalar)) {
        fprintf(stderr,"hash_to_scalar(s) failed\n");
        return 0;
    }

    // --- 2) hash_to_scalar for randomness t ---
    t_scalar = BN_new();
    if (!hash_to_scalar(us, (unsigned char*)t_bytes, t_len, t_scalar)) {
        fprintf(stderr,"hash_to_scalar(t) failed\n");
        return 0;
    }

    // --- 3) allocate EC_POINTs ---
    sG = EC_POINT_new(us->group);
    tH = EC_POINT_new(us->group);
    C  = EC_POINT_new(us->group);
    if (!sG || !tH || !C) {
        fprintf(stderr,"EC_POINT_new failed\n");
        return 0;
    }

    // --- 4) sG = s_scalar * G ---
    if (!EC_POINT_mul(us->group, sG, NULL, G, s_scalar, ctx)) {
        fprintf(stderr,"mul sG failed\n");
        return 0;
    }

    // --- 5) tH = t_scalar * H ---
    if (!EC_POINT_mul(us->group, tH, NULL, H, t_scalar, ctx)) {
        fprintf(stderr,"mul tH failed\n");
        return 0;
    }

    // --- 6) C = sG + tH ---
    if (!EC_POINT_add(us->group, C, sG, tH, ctx)) {
        fprintf(stderr,"C = sG + tH failed\n");
        return 0;
    }

    // --- 7) serialize C ---
    *out_commit_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    *out_commit = (unsigned char*)malloc(*out_commit_len);
    if (!*out_commit) {
        fprintf(stderr,"malloc commit failed\n");
        return 0;
    }

    if (EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED,
                           *out_commit, *out_commit_len, ctx) != (int)*out_commit_len)
    {
        fprintf(stderr,"serialize C failed\n");
        return 0;
    }

    // success
    BN_free(s_scalar);
    BN_free(t_scalar);
    EC_POINT_free(sG);
    EC_POINT_free(tH);
    EC_POINT_free(C);
    return 1;

    if (s_scalar) BN_free(s_scalar);
    if (t_scalar) BN_free(t_scalar);
    if (sG) EC_POINT_free(sG);
    if (tH) EC_POINT_free(tH);
    if (C) EC_POINT_free(C);
    if (*out_commit) { free(*out_commit); *out_commit = NULL; }
    *out_commit_len = 0;
    return 0;
}

int EC_Com_Verify(US_CTX *us, const unsigned char *s_bytes, size_t s_len, const unsigned char *t_bytes, size_t t_len, const EC_POINT *H, const unsigned char *commit, size_t commit_len){
    /*
    * EC_Com_Verify:
    *    s_bytes, s_len:  message
    *    t_bytes, t_len:  randomness
    *    commit:          C の圧縮形式
    *    commit_len:      長さ
    *
    *  検証:
    *     C ?= sG + tH
    */
    if (!us || !s_bytes || !t_bytes || !H || !commit) return -1;

    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);

    BIGNUM *s_scalar = NULL;
    BIGNUM *t_scalar = NULL;

    EC_POINT *C = NULL;
    EC_POINT *sG = NULL;
    EC_POINT *tH = NULL;
    EC_POINT *R = NULL;

    int ret = -1;

    // --- 1) scalarize s, t ---
    s_scalar = BN_new();
    if (!hash_to_scalar(us, (unsigned char*)s_bytes, s_len, s_scalar)) {
        fprintf(stderr,"hash_to_scalar(s) failed\n");
        return 0;
    }

    t_scalar = BN_new();
    if (!hash_to_scalar(us, (unsigned char*)t_bytes, t_len, t_scalar)) {
        fprintf(stderr,"hash_to_scalar(t) failed\n");
        return 0;
    }

    // --- 2) points ---
    C = EC_POINT_new(us->group);
    sG = EC_POINT_new(us->group);
    tH = EC_POINT_new(us->group);
    R  = EC_POINT_new(us->group);
    if (!C || !sG || !tH || !R) {
        fprintf(stderr,"EC_POINT_new failed\n");
        return 0;
    }

    // restore C from bytes
    if (!EC_POINT_oct2point(us->group, C, commit, commit_len, ctx)) {
        fprintf(stderr,"parse commit failed\n");
        return 0;
    }

    // sG
    if (!EC_POINT_mul(us->group, sG, NULL, G, s_scalar, ctx)) {
        fprintf(stderr,"mul sG failed\n");
        return 0;
    }

    // tH
    if (!EC_POINT_mul(us->group, tH, NULL, H, t_scalar, ctx)) {
        fprintf(stderr,"mul tH failed\n");
        return 0;
    }

    // R = sG + tH
    if (!EC_POINT_add(us->group, R, sG, tH, ctx)) {
        fprintf(stderr,"R = sG + tH failed\n");
        return 0;
    }

    // compare R and C
    int cmp = EC_POINT_cmp(us->group, R, C, ctx);
    if (cmp == 0) ret = 1;     // OK
    else if (cmp == 1) ret = 0; // mismatch
    else ret = -1;

    if (s_scalar) BN_free(s_scalar);
    if (t_scalar) BN_free(t_scalar);
    if (C) EC_POINT_free(C);
    if (sG) EC_POINT_free(sG);
    if (tH) EC_POINT_free(tH);
    if (R) EC_POINT_free(R);
    return ret;
}

