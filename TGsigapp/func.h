#ifndef FUNC_H
#define FUNC_H

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctime>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// #include "groupsig/groupsig.h"
// #include "groupsig/gml.h"
// #include "groupsig/kty04.h"
// #include "groupsig/message.h"


#define PORT 9001
#define MAX_FRAME 4096
#define SERVER_ADDR "127.0.0.1"

#define ROUTERS 4
#define NODES   (ROUTERS+2)

#define ETH_LEN 14     // VLAN 無し
#define IP_LEN  20
#define SID_LEN 32
#define CID_LEN 2
#define PUB_LEN 32
#define SEC_LEN 32
#define KEY_LEN 32
#define SEG_LEN 12  // c_i の長さ（固定長にする）
#define TAG_LEN 16
#define IV_LEN  12
#define MAX_SEG_CON (ROUTERS + 1) * (SEG_LEN + TAG_LEN + IV_LEN)
#define SIG_LEN 64
#define GSIG_LEN 2040
#define MAX_PI ((ROUTERS + 1) * SIG_LEN)
#define ACSEG_LEN 32
// #define MAX_ACSEG_CON ROUTERS * ACSEG_LEN
#define MAX_PTXT 1024
#define MAX_PKT  4096
#define MAX_STATE  8

 
extern enum{ SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;
extern const char *router_addresses[];
// extern const char* router_addresses[] = {
//     "192.168.10.0",
//     "192.168.10.1",
//     "192.168.10.2",
//     "192.168.10.3",
//     "192.168.10.4",
//     "192.168.10.5",
//     "192.168.10.6",
//     "192.168.10.7",
//     "192.168.10.8"
// };
extern EVP_MD_CTX *mdctx1, *mdctx2;
extern const char *policy[];
extern const int POLICY_COUNT;


// ========= L2/L3 (Ether/IPv4) ヘッダ =========
typedef struct {
    unsigned char dst[6];
    unsigned char src[6];
    uint16_t ethertype;    // 0x0800 = IPv4
} __attribute__((packed)) EthHdr;

typedef struct {
    uint8_t  ver_ihl;      // version(4) | IHL(4)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t hdr_checksum;
    uint32_t src;
    uint32_t dst;
    // options may follow (IHL>5)
} __attribute__((packed)) IPv4Hdr;

// ---- 共通ヘッダ ----
// SID(32) | CID(2) | STATUS(1) | idx(1)
typedef struct {
    unsigned char sid[SID_LEN];  // セッションID
    unsigned char cid[CID_LEN];      // サーキットID
    uint8_t status;              // ステータス (SETUP_REQ, SETUP_RESP, DATA_TRANS)
    uint8_t idx;                 // ルータインデックス (0=センダー, NODES-1=レシーバ)
    // unsigned char dest[4];       // 宛先アドレス

    // SETUP_REQ
    unsigned char seg_concat[MAX_SEG_CON];         // 暗号化経路情報リストデータ
    // SETUP_REQ / SETUP_RESP ヘッダ: πリスト情報
    unsigned char pi_concat[MAX_PI];         // π リストデータ

    // SETUP_RESP ヘッダ: ρ
    unsigned char rho[2][SIG_LEN];             // ρ データ

    // DATA_TRANS ヘッダ: アカウンタビリティセグメント
    unsigned char acseg_concat[SIG_LEN];       // アカウンタビリティセグメント

} Oheader;

// ---- ペイロード ----
typedef struct {
    
    // SETUP_REQ
    // uint16_t tau_len;
    unsigned char tau[SIG_LEN];       //検証用の署名
    
    // SETUP_RESP
    unsigned char rand_val[4];        //検証用の乱数
    
    // ---- SETUP_REQ / SETUP_RESP ----
    unsigned char peer_pub[PUB_LEN];  // 公開鍵 (k_C または k_S)

    // ---- SETUP_REQ ----
    size_t sig_len;
    unsigned char sig_bytes[GSIG_LEN];  // グループ署名

    // ---- DATA_TRANS ----
    unsigned char iv[IV_LEN];         // GCM-IV
    size_t ct_len;                    // 暗号文長
    unsigned char ct[MAX_PTXT];       // 暗号文
    unsigned char tag[TAG_LEN];       // GCM-タグ
} Payload;

typedef struct {
    Oheader  h;
    Payload p;
} Packet;

typedef struct {
    int id; // ノードID (今回は便宜上0=センダー, NODES-1=レシーバ)
    // char name[8];
    unsigned char addr[4];
    unsigned char rand_val[4];


    // X25519 (DH)
    EVP_PKEY *dh_sk;
    EVP_PKEY *dh_pk;

    // X25519鍵
    EVP_PKEY *sk;
    EVP_PKEY *pk;

    // セッション鍵
    //センダーは全ノード分(k)、レシーバは自ノード分のみ(ki)
    unsigned char k[NODES][KEY_LEN];//各ノードとの共有鍵
    unsigned char ki[KEY_LEN];//センダーと自ノードとの共有鍵

    unsigned char sess_key[KEY_LEN];
    int has_sess;

    // SIDに紐づく前後ホップ状態
    struct {
        int used;
        unsigned char sid[SID_LEN];
        unsigned char precid[CID_LEN]; // サーキットID
        unsigned char nexcid[CID_LEN]; // サーキットID
        char prev_addr; //本来アドレスだが便宜上ノードID
        char next_addr; //本来アドレスだが便宜上ノードID
        char nnext_addr; //本来アドレスだが便宜上ノードID
        unsigned char tau[SIG_LEN];   // τi
        size_t tau_len;
    } state[MAX_STATE];
} Node;

// 関数プロトタイプ宣言
void die(const char *msg);
unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen);
EVP_PKEY* generate_x25519_keypair();
EVP_PKEY* import_x25519_pub(const unsigned char pub[PUB_LEN]);
void hash_sid_from_pub(const unsigned char *pub, unsigned char sid[SID_LEN]);
void get_raw_pub(EVP_PKEY *pkey, unsigned char pub[PUB_LEN]);
void derive_shared(const EVP_PKEY *my_sk, const EVP_PKEY *peer_pub, unsigned char sec[SEC_LEN]);
EVP_PKEY* gen_ed25519_keypair();
EVP_PKEY* extract_public_only(EVP_PKEY *pkey);
int save_ed25519_seckey_pem(EVP_PKEY *pkey, const char *filename);
int save_ed25519_pubkey_pem(EVP_PKEY *pkey, const char *filename);
EVP_PKEY* load_ed25519_seckey_pem(const char *filename);
EVP_PKEY* load_ed25519_pubkey_pem(const char *filename);
void init_crypto(EVP_PKEY *sk, EVP_PKEY *pk);
void print_hex(const char *title, const unsigned char *s, size_t len);
void sha256(const unsigned char *data, size_t data_len, unsigned char hash[32]);
void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]);
int aead_decrypt(const unsigned char key[KEY_LEN], const unsigned char *ct, size_t ct_len, const unsigned char sid[SID_LEN], const unsigned char iv[IV_LEN], const unsigned char tag[TAG_LEN], unsigned char *pt_out);
int hmac_sha256(const unsigned char *key, size_t keylen, const unsigned char *data, size_t datalen, unsigned char out[ACSEG_LEN], unsigned int *out_len);
void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char *sig, size_t *siglen);
int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen);
// void prev_node_init(Node *node, int id, const char *addr);
// void next_node_init(Node *node, int id, const char *addr);
void node_init(Node *node, int id, const char *addr);
void node_free(Node *n);
void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char precid[CID_LEN], unsigned char nexcid[CID_LEN], unsigned char prev_addr, int next_addr, int nnext_addr, const unsigned char *tau, size_t tau_len);
int state_get_next(const Node *n, const unsigned char sid[SID_LEN]);
int state_get_prev(const Node *n, const unsigned char sid[SID_LEN]);
const unsigned char* state_get_tau(const Node *n, const unsigned char sid[SID_LEN]);
int save_pi_list(const unsigned char sid[SID_LEN], const unsigned char *pi_concat, size_t pi_len);
int load_pi_list(const char *filename, unsigned char sid[SID_LEN], unsigned char **pi_out, size_t *pi_len_out);
size_t overlay_header_footprint(void);//固定へッダ長
// L2/L3 ダミーを埋めて最小 IPv4 ヘッダ(IHL = 5)作成
size_t write_l2l3_min(unsigned char *buf, size_t buf_cap);
size_t ipv4_header_len_bytes(const IPv4Hdr *ip);

size_t l3_overlay_offset(const unsigned char *l2);
size_t build_overlay_setup_req(unsigned char *l2, size_t cap, const Packet *pkt);
size_t build_overlay_setup_resp(unsigned char *l2, size_t cap, const Packet *pkt);
size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt);
int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt);
int router_handle_forward(unsigned char *frame, Node *nodes);
int router_handle_reverse(unsigned char *frame, Node *nodes);
int router_handle_data_trans(unsigned char *frame, Node *nodes);
int apply_policy_contract(const char *msg);

#endif
