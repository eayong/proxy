#ifndef __PROXY_SSL_CONTEXT_H__
#define __PROXY_SSL_CONTEXT_H__

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

enum SslVersion
{
    VERSION_SSL_V1,
    VERSION_SSL_V2,
    VERSION_SSL_V3,
    VERSION_TLS_V1_0,
    VERSION_TLS_V1_1,
    VERSION_TLS_V1_2,
};

class SslContext
{
public:
    SslContext(SslVersion type = VERSION_TLS_V1_2);
    ~SslContext();

    int Init();

    SSL_CTX *GetCliCtx() { return m_cliCtx; }

    SSL_CTX *GetServCtx() { return m_servCtx; }

private:
    int InitClient();
    int InitServer();
    void Finish();
    
private:
    SSL_CTX     *m_cliCtx;
    SSL_CTX     *m_servCtx;
    SslVersion  m_type;
};

#endif // __PROXY_SSL_CONTEXT_H__
