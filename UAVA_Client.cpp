#include <relic.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip> 
#include <cstring> // for memcpy
#include <sys/socket.h>
#include <map>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 9002


// === Structs ===
struct GroupPublicKey {
    ep_t g1, h, h1, u, v;
    ep2_t g2, w;
    gt_t e_h_g2, e_h_w, e_g1_g2, e_h1_g2;
};

struct GroupManagerSecretKey {
    bn_t gamma, eta1, eta2;
};

struct GroupMemberKey {
    bn_t x, y;
    ep_t A;
    gt_t eAg2;
};

struct Signature {
    ep_t T1, T2, T3;
    bn_t c, s_alpha, s_beta, s_x, s_delta1, s_delta2, s_y;
};


// === Utility ===
void print_bytes(const std::string &label, const std::vector<uint8_t> &v) {
    std::cout << label << " (" << v.size() << " bytes): ";
    for (auto b : v) printf("%02x", b);
    std::cout << "\n";
}

std::string serialize_gpk(const GroupPublicKey &gpk) {
    int len = ep_size_bin(gpk.g1, 1);
    std::vector<uint8_t> buf(len);
    ep_write_bin(buf.data(), len, gpk.g1, 1);  // Just serialize g1 for now
    return std::string(buf.begin(), buf.end());
}

// === Structs for Our Protocol ===
struct Idv {
    std::string nickname;
    ep_t pk;  // DSS Public Key
};

struct Cert_g {
    Idv idv;
    Signature sigma_g;  // BBS signature on (nickname || pk)
};

// === serialize_idv
std::string serialize_idv(const Idv &idv) {
    int len = ep_size_bin(idv.pk, 1);
    std::vector<uint8_t> buf(len);
    ep_write_bin(buf.data(), len, idv.pk, 1);
    std::string pk_str(buf.begin(), buf.end());
    return idv.nickname + "||" + pk_str;
}
// === serialize_cert_g
std::string serialize_cert_g(const Cert_g &cert) {
    std::string idv_str = serialize_idv(cert.idv);
    int len = ep_size_bin(cert.sigma_g.T1, 1);
    std::vector<uint8_t> buf(len);
    ep_write_bin(buf.data(), len, cert.sigma_g.T1, 1);
    std::string sig_str(buf.begin(), buf.end());
    return idv_str + "||" + sig_str;
}

std::string bn_to_str(const bn_t bn) {
    uint8_t buf[128];
    int len = bn_size_bin(bn);
    bn_write_bin(buf, len, bn);
    return std::string(buf, buf + len);
}

void bn_from_str(bn_t out, const std::string &s) {
    bn_read_bin(out, (const uint8_t *)s.data(), s.size());
}


void append_bytes(std::vector<uint8_t> &out, const ep_t point, const std::string &label) {
    uint8_t buf[65];
    int len = ep_size_bin(point, 1);  // 1 = compressed
    ep_write_bin(buf, len, point, 1);
    out.insert(out.end(), buf, buf + len);
    //print_bytes(label, std::vector<uint8_t>(buf, buf + len));
}

void append_gt_bytes(std::vector<uint8_t> &bytes, gt_t gt, const std::string &label)
 {
    
    int len = gt_size_bin(gt, 0);  // 0 = uncompressed
    //const int len = 1536;  // 0 = uncompressed
    std::vector<uint8_t> buf(len);
    gt_write_bin(buf.data(), len, gt, 0);  // Safe: actual size used
    //print_bytes(label, buf);
    bytes.insert(bytes.end(), buf.begin(), buf.end());


}

void append_msg_bytes(std::vector<uint8_t> &out, const std::string &msg, const std::string &label) {
    std::vector<uint8_t> msg_bytes(msg.begin(), msg.end());
    out.insert(out.end(), msg_bytes.begin(), msg_bytes.end());
    //print_bytes(label, msg_bytes);
}

void hash_to_bn(bn_t out, const std::vector<uint8_t> &data, const bn_t order) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    md_map_sh256(hash, data.data(), data.size());
    bn_read_bin(out, hash, SHA256_DIGEST_LENGTH);
    bn_mod_basic(out, out, order);
}

void print_bn(const bn_t bn) {
    uint8_t buf[256];
    int len = bn_size_bin(bn);
    bn_write_bin(buf, len, bn);
    for (int i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
    }
    std::cout << std::endl;
}

// === BBS Setup ===
void BBS_Setup(GroupPublicKey &gpk, GroupManagerSecretKey &gmsk) {
    core_init();
    ep_param_set_any_pairf();

    bn_t order; bn_new(order); ep_curve_get_ord(order);
    bn_new(gmsk.gamma); bn_new(gmsk.eta1); bn_new(gmsk.eta2);
    bn_rand_mod(gmsk.gamma, order);
    bn_rand_mod(gmsk.eta1, order);
    bn_rand_mod(gmsk.eta2, order);

    ep_new(gpk.g1); ep_new(gpk.h); ep_new(gpk.h1); ep_new(gpk.u); ep_new(gpk.v);
    ep2_new(gpk.g2); ep2_new(gpk.w);
    gt_new(gpk.e_h_g2); gt_new(gpk.e_h_w); gt_new(gpk.e_g1_g2); gt_new(gpk.e_h1_g2);

    ep_curve_get_gen(gpk.g1);
    ep2_curve_get_gen(gpk.g2);
    ep_rand(gpk.h); ep_rand(gpk.h1);

    ep2_mul(gpk.w, gpk.g2, gmsk.gamma);

    bn_t eta1_inv, eta2_inv; bn_new(eta1_inv); bn_new(eta2_inv);
    bn_mod_inv(eta1_inv, gmsk.eta1, order);
    bn_mod_inv(eta2_inv, gmsk.eta2, order);
    ep_mul(gpk.u, gpk.h, eta1_inv);
    ep_mul(gpk.v, gpk.h, eta2_inv);

    pc_map(gpk.e_h_g2, gpk.h, gpk.g2);
    pc_map(gpk.e_h_w, gpk.h, gpk.w);
    pc_map(gpk.e_g1_g2, gpk.g1, gpk.g2);
    pc_map(gpk.e_h1_g2, gpk.h1, gpk.g2);

    //std::cout << "✅ BBS Setup completed\n";
}


// === Join ===
GroupMemberKey BBS_Join(const GroupPublicKey &gpk, const GroupManagerSecretKey &gmsk, const bn_t &order) {
    GroupMemberKey gsk;
    bn_new(gsk.x); bn_new(gsk.y);
    ep_new(gsk.A);
    gt_new(gsk.eAg2);

    bn_rand_mod(gsk.x, order);
    bn_rand_mod(gsk.y, order);

    ep_t h1_yi; ep_new(h1_yi);
    ep_mul(h1_yi, gpk.h1, gsk.y);

    ep_t g1_minus_h1yi; ep_new(g1_minus_h1yi);
    ep_sub(g1_minus_h1yi, gpk.g1, h1_yi);

    bn_t denom, denom_inv;
    bn_new(denom); bn_new(denom_inv);
    bn_add(denom, gsk.x, gmsk.gamma); bn_mod_basic(denom, denom, order);
    bn_mod_inv(denom_inv, denom, order);

    ep_mul(gsk.A, g1_minus_h1yi, denom_inv);
    pc_map(gsk.eAg2, gsk.A, gpk.g2);

    //std::cout << "✅ BBS Join completed\n";
    return gsk;
}

// === Sign ===
Signature BBS_Sign(const GroupPublicKey &gpk, const GroupMemberKey &gsk, const std::string &msg, const bn_t &order) {
    Signature sig;
    ep_new(sig.T1); ep_new(sig.T2); ep_new(sig.T3);
    bn_new(sig.c); bn_new(sig.s_alpha); bn_new(sig.s_beta);
    bn_new(sig.s_x); bn_new(sig.s_y); bn_new(sig.s_delta1); bn_new(sig.s_delta2);

    bn_t alpha, beta, r_alpha, r_beta, r_x, r_y, r_delta1, r_delta2;
    bn_new(alpha); bn_new(beta);
    bn_new(r_alpha); bn_new(r_beta);
    bn_new(r_x); bn_new(r_y);
    bn_new(r_delta1); bn_new(r_delta2);

    // Random secrets
    bn_rand_mod(alpha, order); bn_rand_mod(beta, order);
    bn_rand_mod(r_alpha, order); bn_rand_mod(r_beta, order);
    bn_rand_mod(r_x, order); bn_rand_mod(r_y, order);
    bn_rand_mod(r_delta1, order); bn_rand_mod(r_delta2, order);

    // Compute delta1 = x * alpha, delta2 = x * beta
    bn_t delta1, delta2;
    bn_new(delta1); bn_new(delta2);
    bn_mul(delta1, gsk.x, alpha); bn_mod_basic(delta1, delta1, order);
    bn_mul(delta2, gsk.x, beta); bn_mod_basic(delta2, delta2, order);

   // bn_copy(sig.s_y, r_y); // For now, assign s_y to r_y for reuse

    // T1 = u^alpha, T2 = v^beta
    ep_mul(sig.T1, gpk.u, alpha);
    ep_mul(sig.T2, gpk.v, beta);

    // T3 = A_i + (alpha + beta) * h
    bn_t alpha_plus_beta;
    bn_new(alpha_plus_beta);
    bn_add(alpha_plus_beta, alpha, beta);
    bn_mod_basic(alpha_plus_beta, alpha_plus_beta, order);

    ep_t h_term, t3_tmp;
    ep_new(h_term); ep_new(t3_tmp);

    // Compute (alpha + beta) * h
    ep_mul(h_term, gpk.h, alpha_plus_beta);

    // Compute T3 = A + (alpha + beta) * h
    ep_add(sig.T3, gsk.A, h_term);

    // R1 = u^r_alpha, R2 = v^r_beta
    ep_t R1, R2, R4, R5;
    ep_new(R1); ep_new(R2); ep_new(R3); ep_new(R4); ep_new(R5);
    ep_mul(R1, gpk.u, r_alpha);
    ep_mul(R2, gpk.v, r_beta);

    // R3 = e(T3, g2)^r_x * e(h, w)^-(r_alpha + r_beta) * e(h, g2)^-(r_delta1 + r_delta2) * e(h1, g2)^r_y
    gt_t R3, e1, e2, e3, e4, e5;
    gt_new(R3); gt_new(e1); gt_new(e2); gt_new(e3); gt_new(e4); gt_new(e5);


    pc_map(e1, sig.T3, gpk.g2);
    gt_exp(e1, e1, r_x); // First pairing term

    bn_t neg_r_alpha, neg_r_beta, neg_r_alpha_beta;
    bn_new(neg_r_alpha); bn_new(neg_r_beta); bn_new(neg_r_alpha_beta);

    // Compute -r_alpha and -r_beta individually
    bn_neg(neg_r_alpha, r_alpha);
    bn_neg(neg_r_beta, r_beta);

    // Add the two negated values
    bn_add(neg_r_alpha_beta, neg_r_alpha, neg_r_beta);

    // Reduce modulo the group order
    bn_mod_basic(neg_r_alpha_beta, neg_r_alpha_beta, order);

    gt_exp(e2, gpk.e_h_w, neg_r_alpha_beta); // second pairing term

    bn_t neg_r_delta1_2; bn_new(neg_r_delta1_2);
    bn_add(neg_r_delta1_2, r_delta1, r_delta2);
    bn_neg(neg_r_delta1_2, neg_r_delta1_2); bn_mod_basic(neg_r_delta1_2, neg_r_delta1_2, order);
    
    gt_exp(e3, gpk.e_h_g2, neg_r_delta1_2);

    gt_exp(e4, gpk.e_h1_g2, r_y);


    gt_mul(R3, e1, e2);
    gt_mul(R3, R3, e3);
    gt_mul(R3, R3, e4);
    //gt_mul(R3, R3, e5);

    // R4 = T1^r_x · u^-r_delta1
    ep_t u_d1, u_d1_neg, T1_rx;
    ep_new(u_d1); ep_new(u_d1_neg); ep_new(T1_rx);
    ep_mul(u_d1, gpk.u, r_delta1); ep_neg(u_d1_neg, u_d1);
    ep_mul(T1_rx, sig.T1, r_x); ep_add(R4, T1_rx, u_d1_neg);

    // R5 = T2^r_x · v^-r_delta2
    ep_t v_d2, v_d2_neg, T2_rx;
    ep_new(v_d2); ep_new(v_d2_neg); ep_new(T2_rx);
    ep_mul(v_d2, gpk.v, r_delta2); ep_neg(v_d2_neg, v_d2);
    ep_mul(T2_rx, sig.T2, r_x); ep_add(R5, T2_rx, v_d2_neg);

    // Compute challenge c
    std::vector<uint8_t> hash_input;
    append_bytes(hash_input, sig.T1, "T1");
    append_bytes(hash_input, sig.T2, "T2");
    append_bytes(hash_input, sig.T3, "T3");
    append_bytes(hash_input, R1, "R1");
    append_bytes(hash_input, R2, "R2");
    append_gt_bytes(hash_input, R3, "R3");
    append_bytes(hash_input, R4, "R4");
    append_bytes(hash_input, R5, "R5");
    hash_input.insert(hash_input.end(), msg.begin(), msg.end());

    hash_to_bn(sig.c, hash_input, order);

    // Responses
    bn_mul(sig.s_alpha, sig.c, alpha); bn_add(sig.s_alpha, sig.s_alpha, r_alpha); bn_mod_basic(sig.s_alpha, sig.s_alpha, order);
    bn_mul(sig.s_beta, sig.c, beta); bn_add(sig.s_beta, sig.s_beta, r_beta); bn_mod_basic(sig.s_beta, sig.s_beta, order);
    bn_mul(sig.s_x, sig.c, gsk.x); bn_add(sig.s_x, sig.s_x, r_x); bn_mod_basic(sig.s_x, sig.s_x, order);
    bn_mul(sig.s_y, sig.c, gsk.y); bn_add(sig.s_y, sig.s_y, r_y); bn_mod_basic(sig.s_y, sig.s_y, order);
    bn_mul(sig.s_delta1, sig.c, delta1); bn_add(sig.s_delta1, sig.s_delta1, r_delta1); bn_mod_basic(sig.s_delta1, sig.s_delta1, order);
    bn_mul(sig.s_delta2, sig.c, delta2); bn_add(sig.s_delta2, sig.s_delta2, r_delta2); bn_mod_basic(sig.s_delta2, sig.s_delta2, order);

    return sig;
}


// === Verify ===
bool BBS_Verify(const GroupPublicKey &gpk, const Signature &sig, const std::string &msg, const bn_t &order) {
    // Recompute R1_dash = u^s_alpha · T1^-c
    ep_t R1_dash, R2_dash, R4_dash, R5_dash;
    ep_new(R1_dash); ep_new(R2_dash); ep_new(R4_dash); ep_new(R5_dash);

    ep_t t1_c, t2_c;
    ep_new(t1_c); ep_new(t2_c);

    ep_mul(R1_dash, gpk.u, sig.s_alpha);
    ep_mul(t1_c, sig.T1, sig.c); ep_neg(t1_c, t1_c);
    ep_add(R1_dash, R1_dash, t1_c);

    ep_mul(R2_dash, gpk.v, sig.s_beta);
    ep_mul(t2_c, sig.T2, sig.c); ep_neg(t2_c, t2_c);
    ep_add(R2_dash, R2_dash, t2_c);

    // ========== R3_dash FULL REWRITE ==========
    gt_t R3_dash, e1, e2, e3, e4, e5;
    gt_new(R3_dash); gt_new(e1); gt_new(e2); gt_new(e3); gt_new(e4); gt_new(e5);

    // e1 = e(h, w)^(-s_alpha - s_beta)
    bn_t temp_salpha_sbeta; bn_new(temp_salpha_sbeta);
    bn_add(temp_salpha_sbeta, sig.s_alpha, sig.s_beta);
    bn_neg(temp_salpha_sbeta, temp_salpha_sbeta); bn_mod_basic(temp_salpha_sbeta, temp_salpha_sbeta, order);
    gt_exp(e1, gpk.e_h_w, temp_salpha_sbeta);

    // e2 = e(h, g2)^(-s_delta1 - s_delta2)
    bn_t temp_sdelta1_sdelta2; bn_new(temp_sdelta1_sdelta2);
    bn_add(temp_sdelta1_sdelta2, sig.s_delta1, sig.s_delta2);
    bn_neg(temp_sdelta1_sdelta2, temp_sdelta1_sdelta2); bn_mod_basic(temp_sdelta1_sdelta2, temp_sdelta1_sdelta2, order);
    gt_exp(e2, gpk.e_h_g2, temp_sdelta1_sdelta2);

    // e3 = e(T3, w^c · g2^s_x)
    ep2_t w_c, g2_sx, base;
    ep2_new(w_c); ep2_new(g2_sx); ep2_new(base);
    ep2_mul(w_c, gpk.w, sig.c);
    ep2_mul(g2_sx, gpk.g2, sig.s_x);
    ep2_add(base, w_c, g2_sx);
    pc_map(e3, sig.T3, base);

    // e4 = e(h1, g2)^s_y
    gt_exp(e4, gpk.e_h1_g2, sig.s_y);

    // e5 = (e(g1, g2)^c)^-1
    gt_exp(e5, gpk.e_g1_g2, sig.c);
    gt_inv(e5, e5);

    // Combine all
    gt_mul(R3_dash, e3, e5);
    gt_mul(R3_dash, R3_dash, e1);
    gt_mul(R3_dash, R3_dash, e4);
    gt_mul(R3_dash, R3_dash, e2);

    // R4_dash = T1^s_x · u^-s_delta1
    ep_t u_sd1, u_sd1_neg, T1_sx;
    ep_new(u_sd1); ep_new(u_sd1_neg); ep_new(T1_sx);

    ep_mul(u_sd1, gpk.u, sig.s_delta1); ep_neg(u_sd1_neg, u_sd1);
    ep_mul(T1_sx, sig.T1, sig.s_x); ep_add(R4_dash, T1_sx, u_sd1_neg);

    // R5_dash = T2^s_x · v^-s_delta2
    ep_t v_sd2, v_sd2_neg, T2_sx;
    ep_new(v_sd2); ep_new(v_sd2_neg); ep_new(T2_sx);

    ep_mul(v_sd2, gpk.v, sig.s_delta2); ep_neg(v_sd2_neg, v_sd2);
    ep_mul(T2_sx, sig.T2, sig.s_x); ep_add(R5_dash, T2_sx, v_sd2_neg);

    // === Hash Check ===
    std::vector<uint8_t> bytes;
    append_bytes(bytes, sig.T1, "T1");
    append_bytes(bytes, sig.T2, "T2");
    append_bytes(bytes, sig.T3, "T3");
    append_bytes(bytes, R1_dash, "R1_dash");
    append_bytes(bytes, R2_dash, "R2_dash");
    append_gt_bytes(bytes, R3_dash, "R3_dash");
    append_bytes(bytes, R4_dash, "R4_dash");
    append_bytes(bytes, R5_dash, "R5_dash");
    append_msg_bytes(bytes, msg, "Message");

    bn_t c_dash; bn_new(c_dash);
    hash_to_bn(c_dash, bytes, order);
    //std::cout << "[Debug] Hash (c_dash): "; print_bn(c_dash); std::cout << "\n";

    bool equal = (bn_cmp(sig.c, c_dash) == RLC_EQ);
    //std::cout << "\n🔎 Signature is " << (equal ? "✅ valid" : "❌ invalid") << "\n";
    return equal;
}

void hash_to_bn(bn_t out, const std::string& message, const bn_t order) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    md_map_sh256(hash, (const uint8_t*)message.c_str(), message.length());

    bn_read_bin(out, hash, SHA256_DIGEST_LENGTH);
    bn_mod_basic(out, out, order);  // Reduce mod group order
}
// === DSS Keygen ===
void DSS_Keygen(bn_t sk, ep_t pk) {
    bn_t order; bn_new(order); ep_curve_get_ord(order);
    bn_rand_mod(sk, order);
    ep_mul_gen(pk, sk);
}

// === DSS Sign ===
void DSS_Sign(const bn_t sk, const std::string &message, bn_t sig) {
    bn_t order; bn_new(order); ep_curve_get_ord(order);

    bn_t h;
    bn_new(h);
    hash_to_bn(h, message, order);  // h = H(m)

    bn_mul(sig, sk, h);
    bn_mod_basic(sig, sig, order);
}

// === DSS Verify ===
bool DSS_Verify(const ep_t pk, const std::string &message, const bn_t sig) {
    bn_t order; bn_new(order); ep_curve_get_ord(order);

    bn_t h;
    bn_new(h);
    hash_to_bn(h, message, order);  // h = H(m)

    ep_t left, right;
    ep_new(left);
    ep_new(right);

    ep_mul_gen(left, sig);      // sig * P
    ep_mul(right, pk, h);       // h * pk

    return ep_cmp(left, right) == RLC_EQ;
}

void serialize_gpk(const GroupPublicKey &gpk, std::vector<uint8_t> &out) {
    auto append_ep = [&](const ep_t &e) {
        int len = ep_size_bin(e, 1);
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + sizeof(int));
        std::vector<uint8_t> buf(len);
        ep_write_bin(buf.data(), len, e, 1);
        out.insert(out.end(), buf.begin(), buf.end());
    };
    auto append_ep2 = [&](const ep2_t &e) {
        int len = ep2_size_bin(e, 1);
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + sizeof(int));
        std::vector<uint8_t> buf(len);
        ep2_write_bin(buf.data(), len, e, 1);
        out.insert(out.end(), buf.begin(), buf.end());
    };
    auto append_gt = [&](const gt_t &g) {
        gt_t tmp;
        gt_null(tmp); gt_new(tmp);
        gt_copy(tmp, g);  // copy from const input
    
        int len = gt_size_bin(tmp, 0);  // get correct length
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + sizeof(int));
    
        std::vector<uint8_t> buf(len);
        gt_write_bin(buf.data(), len, tmp, 0);  // uncompressed
    
        out.insert(out.end(), buf.begin(), buf.end());
    
        gt_free(tmp);
    };

    append_ep(gpk.g1); append_ep(gpk.h); append_ep(gpk.h1); append_ep(gpk.u); append_ep(gpk.v);
    append_ep2(gpk.g2); append_ep2(gpk.w);
    append_gt(gpk.e_h_g2); append_gt(gpk.e_h_w); append_gt(gpk.e_g1_g2); append_gt(gpk.e_h1_g2);
}

void deserialize_gpk(GroupPublicKey &gpk, const uint8_t* in) {
    int offset = 0;
    auto read_ep = [&](ep_t &e) {
        int len;
        memcpy(&len, in + offset, sizeof(int));
        offset += sizeof(int);
        std::vector<uint8_t> buf(len);
        memcpy(buf.data(), in + offset, len);
        offset += len;
        ep_new(e);
        ep_read_bin(e, buf.data(), len);
    };
    auto read_ep2 = [&](ep2_t &e) {
        int len;
        memcpy(&len, in + offset, sizeof(int));
        offset += sizeof(int);
        std::vector<uint8_t> buf(len);
        memcpy(buf.data(), in + offset, len);
        offset += len;
        ep2_new(e);
        ep2_read_bin(e, buf.data(), len);
    };
    auto read_gt = [&](gt_t &g) {
        int len;
        memcpy(&len, in + offset, sizeof(int));
        offset += sizeof(int);
        std::vector<uint8_t> buf(len);
        memcpy(buf.data(), in + offset, len);
        offset += len;
        gt_new(g);
        gt_read_bin(g, buf.data(), len);
    };

    read_ep(gpk.g1); read_ep(gpk.h); read_ep(gpk.h1); read_ep(gpk.u); read_ep(gpk.v);
    read_ep2(gpk.g2); read_ep2(gpk.w);
    read_gt(gpk.e_h_g2); read_gt(gpk.e_h_w); read_gt(gpk.e_g1_g2); read_gt(gpk.e_h1_g2);
}
void print_gpk(const GroupPublicKey &gpk) {
    auto print_ep = [](const std::string &label, const ep_t &e) {
        uint8_t buf[65];
        int len = ep_size_bin(e, 1);
        ep_write_bin(buf, len, e, 1);
        std::cout << label << ": ";
        for (int i = 0; i < len; ++i) printf("%02x", buf[i]);
        std::cout << "\n";
    };

    auto print_ep2 = [](const std::string &label, const ep2_t &e) {
        int len = ep2_size_bin(e, 1);
        std::vector<uint8_t> buf(len);
        ep2_write_bin(buf.data(), len, e, 1);
        std::cout << label << ": ";
        for (int i = 0; i < len; ++i) printf("%02x", buf[i]);
        std::cout << "\n";
    };

    auto print_gt = [](const std::string &label, const gt_t &g_const) {
        gt_t g;
        gt_null(g); gt_new(g);
        gt_copy(g, g_const);  // make non-const copy

        int len = gt_size_bin(g, 0);  // 0 = uncompressed
        std::vector<uint8_t> buf(len);
        gt_write_bin(buf.data(), len, g, 0);
        std::cout << label << ": ";
        for (int i = 0; i < len; ++i) printf("%02x", buf[i]);
        std::cout << "\n";

        gt_free(g);
    };

    std::cout << "===== Group Public Key (gpk) =====\n";
    print_ep("g1", gpk.g1);
    print_ep("h", gpk.h);
    print_ep("h1", gpk.h1);
    print_ep("u", gpk.u);
    print_ep("v", gpk.v);
    print_ep2("g2", gpk.g2);
    print_ep2("w", gpk.w);
    print_gt("e_h_g2", gpk.e_h_g2);
    print_gt("e_h_w", gpk.e_h_w);
    print_gt("e_g1_g2", gpk.e_g1_g2);
    print_gt("e_h1_g2", gpk.e_h1_g2);
    std::cout << "==================================\n";
}


// === Signature serialization ===
void serialize_signature(const Signature &sig, std::vector<uint8_t> &out) {
    auto append_ep = [&](const ep_t &e) {
        int len = ep_size_bin(e, 1);
        std::vector<uint8_t> buf(len);
        ep_write_bin(buf.data(), len, e, 1);
        out.insert(out.end(), buf.begin(), buf.end());
    };
    auto append_bn = [&](const bn_t &b) {
        int len = bn_size_bin(b);
        std::vector<uint8_t> buf(len);
        bn_write_bin(buf.data(), len, b);
        out.insert(out.end(), buf.begin(), buf.end());
    };
    append_ep(sig.T1); append_ep(sig.T2); append_ep(sig.T3);
    append_bn(sig.c); append_bn(sig.s_alpha); append_bn(sig.s_beta);
    append_bn(sig.s_x); append_bn(sig.s_delta1); append_bn(sig.s_delta2); append_bn(sig.s_y);
}

/*
// === Signature deserialization (Old) ===
void deserialize_signature(Signature &sig, const uint8_t *in) {
    int offset = 0;
    auto read_ep = [&](ep_t &e) {
        int len = ep_size_bin(e, 1);
        ep_read_bin(e, in + offset, len);
        offset += len;
    };
    auto read_bn = [&](bn_t &b) {
        int len = SHA256_DIGEST_LENGTH;  // Safe lower bound
        bn_new(b);
        bn_read_bin(b, in + offset, len);
        offset += len;
    };
    ep_new(sig.T1); ep_new(sig.T2); ep_new(sig.T3);
    read_ep(sig.T1); read_ep(sig.T2); read_ep(sig.T3);
    read_bn(sig.c); read_bn(sig.s_alpha); read_bn(sig.s_beta);
    read_bn(sig.s_x); read_bn(sig.s_delta1); read_bn(sig.s_delta2); read_bn(sig.s_y);
}

*/


void deserialize_signature(Signature &sig, const uint8_t *in, size_t total_len) {
    size_t offset = 0;

    // helper to read a 32-bit network-order length
    auto read_u32 = [&](uint32_t &v) {
        if (offset + 4 > total_len) throw std::runtime_error("Buffer underrun");
        uint32_t n;
        memcpy(&n, in + offset, 4);
        v = ntohl(n);
        offset += 4;
    };

    // helper to deserialize an EC point
    auto read_ep = [&](ep_t &e) {
        uint32_t len;
        read_u32(len);
        if (offset + len > total_len) throw std::runtime_error("Buffer underrun");
        ep_new(e);
        ep_read_bin(e, in + offset, len);
        offset += len;
    };

    // helper to deserialize a big-number
    auto read_bn = [&](bn_t &b) {
        uint32_t len;
        read_u32(len);
        if (offset + len > total_len) throw std::runtime_error("Buffer underrun");
        bn_new(b);
        bn_read_bin(b, in + offset, len);
        offset += len;
    };

    // Now pull out each field in exactly the same order you serialized them:
    read_ep(sig.T1);
    read_ep(sig.T2);
    read_ep(sig.T3);

    read_bn(sig.c);
    read_bn(sig.s_alpha);
    read_bn(sig.s_beta);
    read_bn(sig.s_x);
    read_bn(sig.s_delta1);
    read_bn(sig.s_delta2);
    read_bn(sig.s_y);

    // (Optionally check offset == total_len here)
}

void serialize_map(const std::map<std::string, std::vector<uint8_t>> &m, std::vector<uint8_t> &out) {
    for (const auto &pair : m) {
        int key_len = pair.first.size();
        int val_len = pair.second.size();

        out.insert(out.end(), reinterpret_cast<uint8_t*>(&key_len), reinterpret_cast<uint8_t*>(&key_len) + sizeof(int));
        out.insert(out.end(), pair.first.begin(), pair.first.end());
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&val_len), reinterpret_cast<uint8_t*>(&val_len) + sizeof(int));
        out.insert(out.end(), pair.second.begin(), pair.second.end());
    }
}

void deserialize_map(std::map<std::string, std::vector<uint8_t>> &m, const uint8_t* in, int total_len) {
    int offset = 0;
    while (offset < total_len) {
        int key_len = 0, val_len = 0;
        memcpy(&key_len, in + offset, sizeof(int)); offset += sizeof(int);
        std::string key(reinterpret_cast<const char*>(in + offset), key_len); offset += key_len;
        memcpy(&val_len, in + offset, sizeof(int)); offset += sizeof(int);
        std::vector<uint8_t> val(in + offset, in + offset + val_len); offset += val_len;
        m[key] = val;
    }
}

// === Authentication Simulation ===
int main() {
    core_init(); ep_param_set_any_pairf();
    //bn_t bpg_order; bn_new(bpg_order); ep_curve_get_ord(bpg_order);
    bn_t order; bn_new(order);
    ep_curve_get_ord(order);

// === Connect to sender ===
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9002);
    inet_pton(AF_INET, "192.168.2.1", &server_addr.sin_addr);
    connect(sock, (sockaddr*)&server_addr, sizeof(server_addr));
    std::cout << "✅ Connected to sender\n";


/*
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server{};
    server.sin_family = AF_INET; server.sin_port = htons(9002);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
    connect(sock, (sockaddr*)&server, sizeof(server));
    std::cout << "✅ Connected to sender\n";
*/
    int gpk_len = 0;
    recv(sock, &gpk_len, sizeof(int), 0);
    std::vector<uint8_t> gpk_buf(gpk_len);
    recv(sock, gpk_buf.data(), gpk_len, 0);
    //std::cout << "📥 Received gpk of length: " << gpk_buf.size() << std::endl;
    GroupPublicKey gpk; deserialize_gpk(gpk, gpk_buf.data());
    std::cout << "📥 gpk received\n";
    //print_gpk(gpk);

    const char* ack = "gpk received";
    send(sock, ack, strlen(ack), 0);

    int auth_len = 0;
    recv(sock, &auth_len, sizeof(int), 0);
    std::vector<uint8_t> auth_buf(auth_len);
    recv(sock, auth_buf.data(), auth_len, 0);
    //std::cout << "📩 Authentication request received\n";

    std::map<std::string, std::vector<uint8_t>> auth_request;
    deserialize_map(auth_request, auth_buf.data(), auth_len);
    auto cert_buf = auth_request["cert_g"];
    auto ts_bytes = auth_request["ts"];
    auto sigma_t_buf = auth_request["sigma_t"];

    std::map<std::string, std::vector<uint8_t>> cert_map;
    deserialize_map(cert_map, cert_buf.data(), cert_buf.size());
    std::vector<uint8_t> Idv_buf = cert_map["Idv_i"];
    std::vector<uint8_t> sig_buf = cert_map["sigma_g"];

    Signature sigma_g;
    deserialize_signature(sigma_g, sig_buf.data(),sig_buf.size());
    bool valid_cert = BBS_Verify(gpk, sigma_g, std::string(Idv_buf.begin(), Idv_buf.end()),order);
    //std::cout << "🔍 cert_g is " << (valid_cert ? "✅ valid" : "❌ invalid") << std::endl;

    std::map<std::string, std::vector<uint8_t>> idv_map;
    deserialize_map(idv_map, Idv_buf.data(), Idv_buf.size());
    auto pk_buf = idv_map["pk_i"];
    ep_t pk_i; ep_new(pk_i);
    ep_read_bin(pk_i, pk_buf.data(), pk_buf.size());

    bn_t hash_ts; bn_new(hash_ts);
    hash_to_bn(hash_ts, ts_bytes, order);

    // Deserialize sigma_t
    bn_t sigma_t; bn_new(sigma_t);
    bn_read_bin(sigma_t, sigma_t_buf.data(), sigma_t_buf.size());

    // Convert ts bytes back to string
    std::string ts(ts_bytes.begin(), ts_bytes.end());

    // Verify timestamp signature
    bool valid_ts = DSS_Verify(pk_i, ts, sigma_t);

    //if (valid_ts)
    //    std::cout << "✅ Timestamp signature valid\n";
    //else
    //    std::cout << "❌ Invalid timestamp signature\n";


    // Decision logic
    std::string response;
    if (valid_cert && valid_ts) {
        //std::cout << "\n🔐 Authentication ✅ PASSED\n";
        response = "Authentication passed";
    } else {
        //std::cout << "\n🔐 Authentication ❌ FAILED\n";
        response = "Authentication failed";
    }

    // Send back the result
    int resp_len = response.size();
    send(sock, &resp_len, sizeof(int), 0);
    send(sock, response.c_str(), resp_len, 0);

    close(sock); core_clean(); return 0;
}