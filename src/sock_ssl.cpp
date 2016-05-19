#include "sock_ssl.h"

extern FILE *g_logFp;
extern void PrintLog(FILE *fp, const char *format...);

SslSocket::SslSocket(int fd, int type, SSL_CTX *sslCtx)
    :Socket(fd, type)
{
    InitCtx(sslCtx);
}

SslSocket::~SslSocket()
{
    Finish();
}

int SslSocket::InitCtx(SSL_CTX *sslCtx)
{
    if (sslCtx == NULL)
    {
        PrintLog(g_logFp, "ssl context is NULL.\n");
        return -1;
    }
    m_pSsl = SSL_new(sslCtx);

    if(NULL == m_pSsl)
    {
        PrintLog(g_logFp, "SSL_new(CTX) failed [%s]\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    
    if(SSL_set_fd(m_pSsl, m_fd) != 1)
    {        
        PrintLog(g_logFp, "SSL_set_fd(%d) failed [%s]\n", m_fd, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    return 0;
}

void SslSocket::Finish()
{
    if(m_pSsl)
    {
        SSL_shutdown(m_pSsl);
        SSL_free(m_pSsl);
        m_pSsl = NULL;
    }
}

int SslSocket::Send(const char *data, uint32_t len)
{
    int n = 0;
    int ret = 0;

    for (;;)
    {
        /* should do a select for the write */
        ret = SSL_write(m_pSsl, data, len);
        switch (SSL_get_error(m_pSsl, ret))
        {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            fprintf(g_logFp, "SSL_write BLOCK\n");
            return 0;
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            fprintf(g_logFp, "SSL_write ERROR, %s\n", ERR_error_string(ERR_get_error(), NULL));
            return -2;
        case SSL_ERROR_ZERO_RETURN:
            return -1;
        }
        if (ret > 0)
        {
            n += ret;
            len -= ret;
        }
        if (len <= 0)
            break;
    }

    return n;

}

int SslSocket::Recv(char *data, uint32_t len)
{
    int nRet = -1;
    uint32_t uReadCount = 0;
    uint32_t uWantRead = len;

    /* SSL handshake has completed? */
    if(!SSL_is_init_finished(m_pSsl))
    {
        char* buffer[1024];
        if((nRet = SSL_read(m_pSsl, buffer, sizeof(buffer))) <= 0)
        {
            nRet = SSL_get_error(m_pSsl, nRet);
            if(nRet == SSL_ERROR_WANT_WRITE || nRet == SSL_ERROR_WANT_READ)
            {
                PrintLog(g_logFp, "SSL_read block, Msg:[%s]\n", nRet, ERR_error_string(ERR_get_error(), NULL));
                nRet = 0;
            }
            else
            {
                PrintLog(g_logFp, "SSL_read failed %d, Msg:[%s]\n", nRet, ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }
        else
        {
            nRet = 0;
        }
        return nRet;
    }

//    while(uWantRead > 0)
//    {
//        if(uReadCount + uWantRead > len)
//        {
//            PrintLog(g_logFp, "SSL_read Warnning too many data to read, bufsize: %d, to readsize: %d\n",
//                len, uReadCount + uWantRead);
//            break;
//        }

//        nRet = SSL_read(m_pSsl, (((uint8_t*)data)+uReadCount), uWantRead);
//        if(nRet <= 0)
//        {
//            nRet = SSL_get_error(m_pSsl, nRet);
//            if(nRet == SSL_ERROR_WANT_WRITE || nRet == SSL_ERROR_WANT_READ)
//            {
//                break;
//            }
//            else if(nRet == SSL_ERROR_ZERO_RETURN)
//            {
//                /*error*/
//                PrintLog(g_logFp, "^--^TLS connection closed.\n");
//                return -1;
//            }
//            else
//            {
//                /*error*/
//                PrintLog(g_logFp, "SSL_read failed %d, Msg:[%s]\n", nRet, ERR_error_string(ERR_get_error(), NULL));
//                return -1;
//            }
//        }
//        else
//        {
//            uReadCount += (uint32_t)nRet;
//        }

//        if((nRet = SSL_pending(m_pSsl)) > 0)
//        {
//            uWantRead = nRet;
//        }
//        else
//        {
//            uWantRead = 0;
//        }
//    }

//    return uReadCount;

    nRet = SSL_read(m_pSsl, data, len);
    if(nRet <= 0)
    {
        nRet = SSL_get_error(m_pSsl, nRet);
        if(nRet == SSL_ERROR_WANT_WRITE || nRet == SSL_ERROR_WANT_READ)
        {
            PrintLog(g_logFp, "^--^TLS read block. %s\n", ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }
        else if(nRet == SSL_ERROR_ZERO_RETURN)
        {
            /*error*/
            PrintLog(g_logFp, "^--^TLS connection closed.\n");
            return -1;
        }
        else
        {
            /*error*/
            PrintLog(g_logFp, "SSL_read failed %d, Msg:[%s]\n", nRet, ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }
    }

    return nRet;
}

int SslSocket::Handshake()
{
    if (m_pSsl == NULL)
    {
        return SOCKET_ERR_SSL;
    }

    if (m_type == SOCKET_SSL_CLIENT)
    {
        SSL_set_connect_state(m_pSsl);
    }
    else if (m_type == SOCKET_SSL_SERVER)
    {
        SSL_set_accept_state(m_pSsl);
    }
    else
    {
        return SOCKET_ERR_SSL;
    }
    
    int ret = SSL_do_handshake(m_pSsl);
    switch (SSL_get_error(m_pSsl, ret))
    {
    case SSL_ERROR_NONE:
        ShowCertificate();
        return SOCKET_ERR_NONE;
        
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_X509_LOOKUP:
        PrintLog(g_logFp, "SSL_do_handshake want blocking %d, Msg: %s\n", ret, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_BLOCK;
        
    case SSL_ERROR_ZERO_RETURN:
        PrintLog(g_logFp, "Socket was close when SSL_do_handshake , Msg: %s\n", ret, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_CLOSE;
        
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
        PrintLog(g_logFp, "SSL_do_handshake failed %d, Msg:[%s]\n", ret, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_SSL;
    }
    return SOCKET_ERR_FAIL;
}

void SslSocket::ShowCertificate()
{
    if (!m_pSsl)
        return;
    X509 *cert = SSL_get_peer_certificate(m_pSsl);
    if (cert != NULL)
    {
        PrintLog(g_logFp, "%s certificate:\n", m_type == SOCKET_SSL_SERVER ? "local" : "remote");
        
        char *str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        if (str == NULL)
            return;
        PrintLog(g_logFp, "\t subject: %s\n", str);
        OPENSSL_free(str);
        
        str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        if (str == NULL)
            return;
        PrintLog(g_logFp, "\t issuer: %s\n", str);
        OPENSSL_free(str);
        
        /* We could do all sorts of certificate verification stuff here before
           deallocating the certificate. */
        
        X509_free(cert);
    }
    else
    {
        PrintLog(g_logFp, "%s has not certificate:\n", m_type == SOCKET_SSL_SERVER ? "local" : "remote");
    }
}

