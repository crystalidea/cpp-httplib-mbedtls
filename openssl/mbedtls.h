#ifndef CPPHTTPLIB_HTTPLIB_MBEDTLS_H
#define CPPHTTPLIB_HTTPLIB_MBEDTLS_H

#include <stdlib.h>
#include <assert.h>

#include <string>
#include <vector>
#include <memory>

#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/debug.h>

#ifdef _WIN32
    
    #include <winsock2.h>

#if MBEDTLS_DEBUG_OUTPUT_LEVEL

    #include <shlwapi.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "Shlwapi.lib")
    #endif

#endif

#endif

#define OPENSSL_VERSION_NUMBER 0x31000000L

#define SSL_VERIFY_NONE         MBEDTLS_SSL_VERIFY_NONE
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02

#define SSL_FILETYPE_PEM    MBEDTLS_X509_FORMAT_PEM

// BIO

struct BIO
{
    BIO(int s) {
        ctx.fd = s;
    }
    ~BIO() {
        mbedtls_net_free(&ctx);
    }

    mbedtls_net_context ctx;

private:

    BIO() {
        mbedtls_net_init(&ctx);
    }
};

#define BIO_NOCLOSE 0

struct SSL;

BIO* BIO_new_socket(int sock, int close_flag)
{
    return new BIO(sock);
}

// If n is zero then blocking I/O is set. If n is 1 then non blocking I/O is set
// TODO: why is here vice versa?? Doesn't work otherwise

void BIO_set_nbio(BIO* bio, long blocking)
{
    if (blocking == 0)
        mbedtls_net_set_nonblock(&bio->ctx); 
    else
        mbedtls_net_set_block(&bio->ctx);
}

BIO* BIO_new_mem_buf(const void* buf, int len)
{
    assert("NOT IMPLEMENTED" == 0);

    return nullptr;
}

void BIO_free_all(BIO* a)
{
    assert("NOT IMPLEMENTED" == 0);
}

// error codes

# define X509_V_OK                                       0
# define X509_V_ERR_UNSPECIFIED                          1
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            2
# define X509_V_ERR_UNABLE_TO_GET_CRL                    3
# define X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     4
# define X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      5
# define X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   6
# define X509_V_ERR_CERT_SIGNATURE_FAILURE               7
# define X509_V_ERR_CRL_SIGNATURE_FAILURE                8
# define X509_V_ERR_CERT_NOT_YET_VALID                   9
# define X509_V_ERR_CERT_HAS_EXPIRED                     10
# define X509_V_ERR_CRL_NOT_YET_VALID                    11
# define X509_V_ERR_CRL_HAS_EXPIRED                      12
# define X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       13
# define X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        14
# define X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       15
# define X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       16
# define X509_V_ERR_OUT_OF_MEM                           17
# define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          18
# define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            19
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    20
# define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      21
# define X509_V_ERR_CERT_CHAIN_TOO_LONG                  22
# define X509_V_ERR_CERT_REVOKED                         23
# define X509_V_ERR_NO_ISSUER_PUBLIC_KEY                 24
# define X509_V_ERR_PATH_LENGTH_EXCEEDED                 25
# define X509_V_ERR_INVALID_PURPOSE                      26
# define X509_V_ERR_CERT_UNTRUSTED                       27
# define X509_V_ERR_CERT_REJECTED                        28

#define SSL_ERROR_ZERO_RETURN           6 // see SSL_peek

#define SSL_ERROR_WANT_READ MBEDTLS_ERR_SSL_WANT_READ
#define SSL_ERROR_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE
#define SSL_ERROR_SYSCALL -0x6785 // TODO: match SSL_ERROR_SYSCALL error code to mbedtls

// x509 stuff

struct X509 {

    X509() // empty cert 
    {
        mbedtls_x509_crt_init(&crt);
    }
    X509(mbedtls_x509_crt* crt_another) // to be used in a SSLClient for example
        : X509()
    {
        int nParseResult = mbedtls_x509_crt_parse_der(&crt, crt_another->raw.p, crt_another->raw.len);

        assert(nParseResult == 0);
    }

    X509(const char* file)
        : X509()
    {
        int ret = mbedtls_x509_crt_parse_file(&crt, file, MBEDTLS_X509_FORMAT_PEM);

        assert(ret == 0);
    }

    ~X509()
    {
        mbedtls_x509_crt_free(&crt);
    }

    mbedtls_x509_crt crt;
};

struct X509_CRL {
    // not used yet
};

struct X509_STORE {

    X509_STORE()
    {
        mbedtls_x509_crt_init(&chain);
        mbedtls_x509_crl_init(&crl_chain);
    }

    ~X509_STORE()
    {
        mbedtls_x509_crt_free(&chain);
        mbedtls_x509_crl_free(&crl_chain);
    }

    mbedtls_x509_crt chain;
    mbedtls_x509_crl crl_chain;
};

struct X509_INFO {
    X509* x509;
    X509_CRL* crl;
};

struct X509_NAME_OPENSSL // originally X509_NAME bug there's a name conflict on Windows
{
    X509_NAME_OPENSSL(const char* sz)
        : str(sz)
    {

    }

    std::string str;
};

# define GEN_DNS         2
# define GEN_IPADD       7

#define NID_subject_alt_name            85

struct GENERAL_NAME_D
{
    const struct GENERAL_NAME* ia5;
};

struct GENERAL_NAME
{
    GENERAL_NAME(int t, const std::vector<unsigned char>& b)
        : type(t), buffer(b)
    {
        d.ia5 = this;
    }

    GENERAL_NAME(const GENERAL_NAME& copy)
    {
        this->type = copy.type;
        this->buffer = copy.buffer;
        this->d.ia5 = this; // !
    }

    GENERAL_NAME(const GENERAL_NAME&& copy)
    {
        this->type = copy.type;
        this->buffer = copy.buffer;
        this->d.ia5 = this;
    }

    std::vector<unsigned char> buffer;

    int type = 0;

    GENERAL_NAME_D d;
};

struct stack_st_GENERAL_NAME
{
    std::vector<GENERAL_NAME> names;
};

inline const char* ASN1_STRING_get0_data(const GENERAL_NAME* s) {

    if (s->type == GEN_DNS)

        return (const char*)&s->buffer[0];

    return nullptr;
}

inline size_t ASN1_STRING_length(const GENERAL_NAME* s) {

    return s->buffer.size();

}

#define STACK_OF(a) a

X509* d2i_X509(void* unused, const unsigned char** p, int len) // decode a DER buffer
{
    std::unique_ptr< X509> cert(new X509());

    int nParseResult = mbedtls_x509_crt_parse_der(&cert->crt, *p, len);

    if (nParseResult == 0)
        return cert.release();

    //assert(0); // failed on one certificate on my windows... (unknown sig)

    return nullptr;
}

X509* PEM_read_X509(FILE* fp, void*, void*, void*)
{
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        std::vector<unsigned char> data;
        data.resize(fsize);

        fread(&data[0], fsize, 1, fp);

        std::unique_ptr<X509> crt(new X509());

        int ret = mbedtls_x509_crt_parse(&crt->crt, &data[0], fsize, MBEDTLS_X509_FORMAT_PEM);

        if (ret == 0)
            return crt.release();
    }

    return nullptr;
}

int X509_STORE_add_cert(X509_STORE* store, X509* toAdd)
{
    // https://stackoverflow.com/questions/63478088/use-mbedtls-to-pull-public-certificate-chain-from-a-server-and-store-as-a-string

    int nParseResult = mbedtls_x509_crt_parse_der(&store->chain, toAdd->crt.raw.p, toAdd->crt.raw.len);

    assert(nParseResult == 0);

    return (nParseResult == 0) ? 1 : 0;
}

int X509_STORE_add_crl(X509_STORE* ctx, X509_CRL* x)
{
    assert("NOT IMPLEMENTED" == 0);

    return 0;
}

void X509_free(X509* cert)
{
    if (cert)
        delete cert;
}

X509_STORE* X509_STORE_new()
{
    return new X509_STORE();;
}

void X509_STORE_free(X509_STORE* store)
{
    if (store)
        delete store;
}

X509_INFO* PEM_X509_INFO_read_bio(BIO* bp, void*, void*, void*)
{
    assert("NOT IMPLEMENTED" == 0);

    return nullptr;
}

int sk_X509_INFO_num(X509_INFO*)
{
    assert("NOT IMPLEMENTED" == 0);

    return 0;
}

X509_INFO* sk_X509_INFO_value(X509_INFO* c, int num)
{
    assert("NOT IMPLEMENTED" == 0);

    return nullptr;
}

void X509_INFO_free(X509_INFO* info)
{
    assert("NOT IMPLEMENTED" == 0);
}

typedef void (*freefunc)(X509_INFO*);

void sk_X509_INFO_pop_free(X509_INFO* info, freefunc)
{
    assert("NOT IMPLEMENTED" == 0);
}

X509_NAME_OPENSSL* X509_get_subject_name(const X509* x)
{
    const mbedtls_x509_name* name = &x->crt.subject;

    char subject_name[512]; // same as BUFSIZ in httplib
    return (mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), name) > 0) ? new X509_NAME_OPENSSL(subject_name) : nullptr;
}

#define NID_commonName 1

int X509_NAME_get_text_by_NID(X509_NAME_OPENSSL* name, int nid, char* buf, int len)
{
    if (buf && nid == NID_commonName)
    {
        static const std::regex cn_regex = std::regex(".*CN=(.+?)");
        std::smatch match;
        std::string in_str = name->str;

        if (std::regex_match(in_str, match, cn_regex))
        {
            if (match.size() == 2) {
                std::string cname = match[1];

                strncpy_s(buf, len, cname.c_str(), cname.size());

                return cname.size();
            }
        }
    }

    return -1; // error
}

stack_st_GENERAL_NAME* X509_get_ext_d2i(X509* x509, int nid, void*, void*)
{
    // taken from the x509_parse_san test

    const mbedtls_x509_crt* crt = &x509->crt;
    const mbedtls_x509_sequence* cur = &crt->subject_alt_names;

    char buf[2000];

    mbedtls_x509_subject_alternative_name san;

    if (crt->private_ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)
    {
        if (nid == NID_subject_alt_name)
        {
            stack_st_GENERAL_NAME* retNames = new stack_st_GENERAL_NAME();

            while (cur)
            {
                memset(buf, 0, 2000);

                int ret = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
                assert(ret == 0 || ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE);

                if (ret == 0) {

                    if (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_IP_ADDRESS)
                    {
                        std::vector<unsigned char> data;
                        data.resize(san.san.unstructured_name.len);
                        memcpy_s(&data[0], data.size(), san.san.unstructured_name.p, san.san.unstructured_name.len);

                        retNames->names.push_back(GENERAL_NAME(san.type == MBEDTLS_X509_SAN_DNS_NAME ? GEN_DNS : GEN_IPADD, data));
                    }

                    mbedtls_x509_free_subject_alt_name(&san);

                }
                cur = cur->next;
            }

            return retNames;
        }
    }

    return nullptr;
}

int sk_GENERAL_NAME_num(const stack_st_GENERAL_NAME* sgn)
{
    return sgn->names.size();
}

const GENERAL_NAME* sk_GENERAL_NAME_value(const stack_st_GENERAL_NAME* sgn, size_t num)
{
    if (num < sgn->names.size())
        return &sgn->names[num];
    return nullptr;
}

void GENERAL_NAMES_free(GENERAL_NAME* sgn)
{
    if (sgn)
    {
        stack_st_GENERAL_NAME* stkgn = reinterpret_cast<stack_st_GENERAL_NAME*>(sgn);

        delete stkgn;
    }

}

// SSL CTX

inline int TLS_client_method(void) {
    return MBEDTLS_SSL_IS_CLIENT;
}

inline int TLS_server_method() {
    return MBEDTLS_SSL_IS_SERVER;
}

inline int TLS_method() {
    return TLS_server_method(); // not sure
}

#include "evp.h"

struct SSL_CTX
{
    SSL_CTX(int endpoint) {
        // own cert and private ket 
        mbedtls_x509_crt_init(&crt);
        mbedtls_pk_init(&pkey);

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "httplib";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

        assert(ret == 0);

        mbedtls_ssl_config_init(&conf_);
        mbedtls_ssl_config_defaults(&conf_, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

        // OPTIONAL is not optimal for security, but makes interop easier in this simplified example
        mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_OPTIONAL); // SSL_set_verify will set it to REQUIRED if needed
        //mbedtls_ssl_conf_ca_chain(&conf_, &cacert, NULL);
        mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg);

#if MBEDTLS_DEBUG_OUTPUT_LEVEL // if you want additional mbetls debug output
        mbedtls_ssl_conf_dbg(&conf_, &SSL_CTX::my_debug, stdout);
        mbedtls_debug_set_threshold(MBEDTLS_DEBUG_OUTPUT_LEVEL);
#endif

        store = X509_STORE_new();
    }

    ~SSL_CTX()
    {
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pkey);

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        mbedtls_ssl_config_free(&conf_);

        X509_STORE_free(store);
    }

    static void my_debug(void* ctx, int debug_level, const char* file, int lineNumber, const char* message)
    {
        char path_short[255];
        strncpy_s(path_short, file, sizeof(path_short));

#if MBEDTLS_DEBUG_OUTPUT_LEVEL
        ::PathStripPathA(path_short);
#endif

        std::cout << path_short << ":" << lineNumber << " " << message << std::endl;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* Own cert & private key */
    mbedtls_x509_crt crt;
    mbedtls_pk_context pkey;

    mbedtls_ssl_config conf_;

    X509_STORE* store = nullptr;
};


SSL_CTX* SSL_CTX_new(int ssl_method)
{
    return new SSL_CTX(ssl_method);
}

void SSL_CTX_free(SSL_CTX* p)
{
    delete p;
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath)
{
    return 1; // success
}

// SSL_CTX_set_default_verify_paths() specifies that the default locations from which CA certificates are loaded should be used. 
// There is one default directory, one default file and one default store.

int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx)
{
    return 1; // success, mbedtls doesn't have this
}

X509_STORE* SSL_CTX_get_cert_store(const SSL_CTX* ctx)
{
    return ctx->store;
}

void SSL_CTX_set_cert_store(SSL_CTX* ctx, X509_STORE* store)
{
    assert("NOT IMPLEMENTED" == 0);
}

int SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x)
{
    int ret = mbedtls_x509_crt_parse_der(&ctx->crt, x->crt.raw.p, x->crt.raw.len);

    return (ret == 0);
}

// type is not used here, it's PEM only at the moment 

int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type)
{
    int ret = mbedtls_x509_crt_parse_file(&ctx->crt, file, type);

    return (ret == 0) ? 1 : 0;
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)
{
    if (mbedtls_pk_parse_keyfile(&ctx->pkey, file, NULL, mbedtls_ctr_drbg_random, &ctx->ctr_drbg) == 0)
    {
        return (mbedtls_ssl_conf_own_cert(&ctx->conf_, &ctx->crt, &ctx->pkey) == 0) ? 1 : 0;
    }

    return 0;
}

struct EVP_PKEY {

    EVP_PKEY(const char* file)
        : file_name(file)
    {

    }
    ~EVP_PKEY() {

    }

    std::string file_name;
};

struct EVP_MD {

};

struct EVP_MD_CTX {

    EVP_MD_CTX();
    ~EVP_MD_CTX();

    void* context = nullptr;

    const EVP_MD* algo = nullptr;
};

const EVP_MD* EVP_md5()
{
    static EVP_MD md;

    return &md;
}

const EVP_MD* EVP_sha256()
{
    static EVP_MD md;

    return &md;
}

const EVP_MD* EVP_sha512()
{
    static EVP_MD md;

    return &md;
}

void EVP_PKEY_free(EVP_PKEY* pkey)
{
    if (pkey)
        delete pkey;
}

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey)
{
    return SSL_CTX_use_PrivateKey_file(ctx, pkey->file_name.c_str(), 0);
}

#define SSL_OP_BIT(n)  ((uint64_t)1 << (uint64_t)n)

# define SSL_OP_NO_COMPRESSION                           SSL_OP_BIT(17)
# define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   SSL_OP_BIT(16)

long SSL_CTX_set_options(SSL_CTX* ctx, long options) // only for server
{
    // NOT YET IMPLEMENTED

    return 0;
}

# define TLS1_1_VERSION                  0x0302

int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) // only for server
{
    mbedtls_ssl_conf_min_version(&ctx->conf_, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    return 1;
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX* ctx, void* u) // only for server
{
    assert("NOT IMPLEMENTED" == 0);
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) // only for server
{
    return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, void*)
{
    assert("NOT IMPLEMENTED" == 0); // only for server
}

// SSL

struct SSL
{
    SSL(SSL_CTX* ctx)
        : ssl_ctx(ctx)
    {
        mbedtls_ssl_init(&mbedtls_ctx);

        int ret = mbedtls_ssl_setup(&mbedtls_ctx, &ssl_ctx->conf_);
        assert(ret == 0);
    }

    ~SSL()
    {
        mbedtls_ssl_free(&mbedtls_ctx);

        if (rbio)
            delete rbio;

        if (wbio != rbio)
            delete wbio;
    }

    mbedtls_ssl_context mbedtls_ctx;

    BIO* rbio = nullptr;
    BIO* wbio = nullptr;

    /* last SSL error. see SSL_get_error implementation. */
    int last_error = 0;

    SSL_CTX* ssl_ctx = nullptr; // parent context
};

int SSL_get_error(const SSL* ssl, int ret) {
    (void)ret;
    return ssl->last_error;
}

SSL* SSL_new(SSL_CTX* ctx)
{
    return new SSL(ctx);
}

void SSL_shutdown(SSL* ssl)
{
    // no code
}

void SSL_free(SSL* ssl)
{
    if (ssl)
        delete ssl;
}

void SSL_set_verify(SSL* ssl, int auth_mode, void*)
{
    // not used
}

int SSL_write(SSL* ssl, const void* buf, int num) {

    // use mbedtls_net_send ?

    ssl->last_error = mbedtls_ssl_write(&ssl->mbedtls_ctx, (const unsigned char*)buf, num);
    return ssl->last_error;
}

int SSL_pending(const SSL* ssl)
{
    // mbedtls_ssl_check_pending returns 0 if nothing’s pending, 1 otherwise.
    return mbedtls_ssl_check_pending(&ssl->mbedtls_ctx) > 0;
}

int SSL_read(SSL* ssl, void* buf, int num)
{
    // use mbedtls_net_recv ?
    // TODO: match SSL_ERROR_SYSCALL error code to mbedtls

    ssl->last_error = mbedtls_ssl_read(&ssl->mbedtls_ctx, (unsigned char*)buf, num);
    return ssl->last_error;
}

// SSL_peek_ex() and SSL_peek() are identical to SSL_read_ex() and SSL_read() respectively except 
// no bytes are actually removed from the underlying BIO during the read, so that a subsequent 
// call to SSL_read_ex() or SSL_read() will yield at least the same bytes.
int SSL_peek(SSL* ssl, void* buf, int num) // only used in ClientImpl::process_request
{
    // not supported in mbedtls, but you can use what mbedtls_net_accept uses
    // https://github.com/Mbed-TLS/mbedtls/pull/563
    // https://github.com/Mbed-TLS/mbedtls/issues/551
    // BTW: httlib has httplib::detail::read_socket

    int fd = ssl->rbio->ctx.fd;
    int ret = recvfrom(fd, (char*)buf, num, MSG_PEEK, nullptr, nullptr);

    ssl->last_error = 0;

    if (ret == 0)
        ssl->last_error = SSL_ERROR_ZERO_RETURN;

    return ret; // <= 0 - The read operation was not successful
}

// SSL_connect() initiates the TLS/SSL handshake with a server. The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
// https://www.openssl.org/docs/man3.1/man3/SSL_connect.html

int SSL_connect(SSL* ssl)
{
    //mbedtls_ssl_conf_verify(&conf, my_cert_verify, this);
    //mbedtls_ssl_set_verify()

    mbedtls_ssl_conf_ca_chain(&ssl->ssl_ctx->conf_, &ssl->ssl_ctx->store->chain, NULL);

    //int ret = mbedtls_ssl_setup(&ssl->mbedtls_ctx, &ssl->ssl_ctx->conf_);
    //assert(ret == 0);

    do {
        ssl->last_error = mbedtls_ssl_handshake(&ssl->mbedtls_ctx);

        if (ssl->last_error < 0)
        {
            assert(0);

            return 0;
        }

    } while (ssl->last_error == MBEDTLS_ERR_SSL_WANT_READ ||
        ssl->last_error == MBEDTLS_ERR_SSL_WANT_WRITE);

    return 1;
}

#define SSL_MODE_AUTO_RETRY 0

void SSL_clear_mode(SSL* ssl, long mode)
{
    // not implemented
}

int SSL_set_tlsext_host_name(SSL* s, const char* name)
{
    return (mbedtls_ssl_set_hostname(&s->mbedtls_ctx, name) == 0) ? 1 : 0;
}

void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio)
{
    ssl->rbio = rbio;
    ssl->wbio = wbio;

    mbedtls_ssl_set_bio(&ssl->mbedtls_ctx, &ssl->rbio->ctx, mbedtls_net_send, mbedtls_net_recv, NULL);
}

#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS    0x00100000L
#define OPENSSL_INIT_LOAD_SSL_STRINGS       0x00200000L
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L

int OPENSSL_init_ssl(uint64_t opts, int settings)
{

    return 1;
}

# define SSL_CTRL_SET_TLSEXT_HOSTNAME            55
/* NameType value from RFC3546 */
# define TLSEXT_NAMETYPE_host_name 0

long SSL_ctrl(SSL* ssl, int cmd, long larg, void* parg)
{
    if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME && larg == TLSEXT_NAMETYPE_host_name)
        return SSL_set_tlsext_host_name(ssl, (const char *)parg);
    else
    {
        assert(0);
    }

    return 0;
}

// verification stuff

long SSL_get_verify_result(const SSL* ssl)
{
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl->mbedtls_ctx);
    
    if (flags != 0)
    {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        // match some common error codes

        if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
            return X509_V_ERR_CERT_HAS_EXPIRED;
        else if (flags & MBEDTLS_X509_BADCERT_REVOKED)
            return X509_V_ERR_CERT_REVOKED;
        else if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
            return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
        else if (flags & MBEDTLS_X509_BADCERT_FUTURE)
            return X509_V_ERR_CERT_NOT_YET_VALID;
        else if (flags & MBEDTLS_X509_BADCRL_FUTURE)
            return X509_V_ERR_CRL_NOT_YET_VALID;
        else
            return X509_V_OK + flags; // no match
    }

    return X509_V_OK;
}

X509* SSL_get_peer_certificate(const SSL* ssl)
{
    std::unique_ptr< X509> ret_cert(new X509());

    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl->mbedtls_ctx);

    if (crt)
    {
        int nParseResult = mbedtls_x509_crt_parse_der(&ret_cert->crt, crt->raw.p, crt->raw.len);

        if (nParseResult == 0)
            return ret_cert.release();
    }

    return nullptr;
}

X509* SSL_get1_peer_certificate(const SSL* ssl)
{
    return SSL_get_peer_certificate(ssl);
}

int SSL_accept(SSL* ssl)
{
    int ret = mbedtls_ssl_handshake(&ssl->mbedtls_ctx);

    if (ret == MBEDTLS_ERR_RSA_VERIFY_FAILED)
    {
        assert("MBEDTLS_ERR_RSA_VERIFY_FAILED issue not solved" == 0);
    }

    assert(ret == 0);

    return (ret == 0) ? 1 : 0;
}

// EVP STUF
/////////////////////////////////////////////////

# define EVP_MAX_MD_SIZE                 64 /* longest known is SHA512 */



EVP_MD_CTX* EVP_MD_CTX_new()
{
    return new EVP_MD_CTX();
}

void EVP_MD_CTX_free(EVP_MD_CTX* ctx)
{
    delete ctx;
}

int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* unused)
{
    ctx->algo = type;

    if (type == EVP_md5())
    {
        ctx->context = malloc(sizeof(mbedtls_md5_context));
        mbedtls_md5_init((mbedtls_md5_context *)ctx->context);
        mbedtls_md5_starts((mbedtls_md5_context*)ctx->context);
    }
    else if (type == EVP_sha256())
    {
        ctx->context = malloc(sizeof(mbedtls_sha256_context));
        mbedtls_sha256_init((mbedtls_sha256_context*)ctx->context);
        mbedtls_sha256_starts((mbedtls_sha256_context*)ctx->context, 0);
    }
    else if (type == EVP_sha512())
    {
        ctx->context = malloc(sizeof(mbedtls_sha512_context));
        mbedtls_sha512_init((mbedtls_sha512_context*)ctx->context);
        mbedtls_sha512_starts((mbedtls_sha512_context*)ctx->context, 0);
    }
    else
    {
        return 0;
    }

    return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)
{
    if (ctx->algo == EVP_md5())
    {
        mbedtls_md5_update((mbedtls_md5_context*)ctx->context, (const unsigned char* )d, cnt);
    }
    else if (ctx->algo == EVP_sha256())
    {
        mbedtls_sha256_update((mbedtls_sha256_context*)ctx->context, (const unsigned char*)d, cnt);
    }
    else if (ctx->algo == EVP_sha512())
    {
        mbedtls_sha512_update((mbedtls_sha512_context*)ctx->context, (const unsigned char*)d, cnt);
    }
    else
    {
        return 0;
    }

    return 1;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)
{
    if (ctx->algo == EVP_md5())
    {
        mbedtls_md5_finish((mbedtls_md5_context*)ctx->context, md);
        *s = 16;
    }
    else if (ctx->algo == EVP_sha256())
    {
        mbedtls_sha256_finish((mbedtls_sha256_context*)ctx->context, md);
        *s = 32;
    }
    else if (ctx->algo == EVP_sha512())
    {
        mbedtls_sha512_finish((mbedtls_sha512_context*)ctx->context, md);
        *s = 64;
    }
    else
    {
        return 0;
    }

    return 1;
}

EVP_MD_CTX::EVP_MD_CTX()
{
    
    
}

EVP_MD_CTX::~EVP_MD_CTX()
{
    if (context)
    {
        if (algo == EVP_md5())
        {
            mbedtls_md5_free((mbedtls_md5_context*)context);
        }
        else if (algo == EVP_sha256())
        {
            mbedtls_sha256_free((mbedtls_sha256_context*)context);
        }
        else if (algo == EVP_sha512())
        {
            mbedtls_sha512_free((mbedtls_sha512_context*)context);
        }

        free(context);
    }
}


#endif // CPPHTTPLIB_HTTPLIB_MBEDTLS_H
