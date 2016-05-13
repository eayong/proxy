#include <string>
#include "ssl_context.h"

using namespace std;

extern string g_cert_path;
extern string g_key_path;
extern FILE *g_logFp;

extern void PrintLog(FILE *fp, const char *format...);


SslContext::SslContext(SslVersion type)
    :m_cliCtx(NULL), m_servCtx(NULL), m_type(type)
{
}

SslContext::~SslContext()
{
    Finish();
}

int SslContext::Init()
{
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();

    if (InitClient() < 0 || InitServer() < 0)
    {
        return -1;
    }
    return 0;
}


int SslContext::InitClient()
{
    switch (m_type)
    {
    case VERSION_SSL_V1:
    case VERSION_SSL_V2:
        PrintLog(g_logFp, "This version is not allowed...\n");
        break;
    case VERSION_SSL_V3:
        PrintLog(g_logFp, "It is not recommended to use this version...\n");
        m_cliCtx = SSL_CTX_new(SSLv3_client_method());
        break;
    case VERSION_TLS_V1_0:
        m_cliCtx = SSL_CTX_new(TLSv1_client_method());
        break;
    case VERSION_TLS_V1_1:
        m_cliCtx = SSL_CTX_new(TLSv1_1_client_method());
        break;
    case VERSION_TLS_V1_2:
        m_cliCtx = SSL_CTX_new(TLSv1_2_client_method());
        break;
    default:
        PrintLog(g_logFp, "Unkown ssl version %d.\n", m_type);
        break;
    }
    if (m_cliCtx == NULL)
    {
        PrintLog(g_logFp, "SSL_CTX_new client context error.\n");
        return -1;
    }

    return 0;
}

int SslContext::InitServer()
{
    switch (m_type)
    {
    case VERSION_SSL_V1:
    case VERSION_SSL_V2:
        PrintLog(g_logFp, "This version is not allowed...\n");
        break;
    case VERSION_SSL_V3:
        PrintLog(g_logFp, "It is not recommended to use this version...\n");
        m_servCtx = SSL_CTX_new(SSLv3_server_method());
        break;
    case VERSION_TLS_V1_0:
        m_servCtx = SSL_CTX_new(TLSv1_server_method());
        break;
    case VERSION_TLS_V1_1:
        m_servCtx = SSL_CTX_new(TLSv1_1_server_method());
        break;
    case VERSION_TLS_V1_2:
        m_servCtx = SSL_CTX_new(TLSv1_2_server_method());
        break;
    default:
        PrintLog(g_logFp, "Unkown ssl version %d.\n", m_type);
        break;
    }
    if (m_servCtx == NULL)
    {
        PrintLog(g_logFp, "SSL_CTX_new server context error.\n");
        return -1;
    }
    
    if (SSL_CTX_use_certificate_file(m_servCtx, g_cert_path.c_str(),  SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(m_servCtx, g_key_path.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!SSL_CTX_check_private_key(m_servCtx))
    {
        PrintLog(g_logFp, "Private key does not match the certificate public key\n");
        return -1;
    }
    return 0;
}

void SslContext::Finish()
{
    if (m_cliCtx != NULL)
    {
        SSL_CTX_free(m_cliCtx);
        m_cliCtx = NULL;
    }
    
    if (m_servCtx != NULL)
    {
        SSL_CTX_free(m_servCtx);
        m_servCtx = NULL;
    }
}

