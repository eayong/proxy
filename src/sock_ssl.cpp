#include "sock_ssl.h"

SslSocket::SslSocket(int fd, SSL_CTX *sslCtx)
    :Socket(fd)
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
        printf("ssl context is NULL.\n");
        return -1;
    }
    m_pSsl = SSL_new(sslCtx);

    if(NULL == m_pSsl)
    {
        printf("SSL_new(CTX) failed [%s]\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    
    if(SSL_set_fd(m_pSsl, m_fd) != 1)
    {        
        printf("SSL_set_fd(%d) failed [%s]\n", m_fd, ERR_error_string(ERR_get_error(), NULL));
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
    bool bWantRead = true;
    bool bTryAgain = true;
    bool bWantWrite = true;
    int nRet = -1;
    int nErrCode = 0;

    nRet = SSL_write(m_pSsl, data, len);
    if(nRet <= 0)
    {
        nErrCode = SSL_get_error(m_pSsl, nRet);
        bWantRead = (nRet == SSL_ERROR_WANT_READ);
        bWantWrite = (nRet == SSL_ERROR_WANT_WRITE);
        if(bWantWrite || bWantRead)
        {
            return 0;
        }
        else
        {
			//printf("Send error:%d err:%d\n", nRet,nErrCode);
            return -1;
        }
    }

    return nRet;

}

int SslSocket::Recv(char *data, uint32_t len)
{
    int nRet = -1;
    uint32_t uReadCount = 0;
    uint32_t uWantRead = 0;
    uWantRead = len;

    bool isEncrypted = SSL_is_init_finished(m_pSsl) ? false: true;

    /* SSL handshake has completed? */
    if(isEncrypted)
    {
        char* buffer[1024];
        if((nRet = SSL_read(m_pSsl, buffer, sizeof(buffer))) <= 0)
        {
            nRet = SSL_get_error(m_pSsl, nRet);
            if(nRet == SSL_ERROR_WANT_WRITE || nRet == SSL_ERROR_WANT_READ)
            {
                nRet = 0;
            }
            else
            {
                printf("SSL_read failed %d, Msg:[%s]\n", nRet, ERR_error_string(ERR_get_error(), NULL));
            }
        }
        else
        {
            nRet = 0;
        }
        return nRet;
    }
    while(uWantRead > 0)
    {
        if(uReadCount + uWantRead > len)
        {
            printf("SSL_read Warnning too many data to read, bufsize: %d, to readsize: %d\n",
                len, uReadCount + uWantRead);
            break;
        }

        nRet = SSL_read(m_pSsl, (((uint8_t*)data)+uReadCount), uWantRead);
        if(nRet <= 0)
        {
            nRet = SSL_get_error(m_pSsl, nRet);
            if(nRet == SSL_ERROR_WANT_WRITE || nRet == SSL_ERROR_WANT_READ)
            {
                break;
            }
            else if(nRet == SSL_ERROR_ZERO_RETURN)
            {
                /*error*/
                printf("^--^TLS connection closed.\n");
                return -1;
            }
            else
            {
                /*error*/
                printf("SSL_read failed %d, Msg:[%s]\n", nRet, ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }
        else
        {
            uReadCount += (uint32_t)nRet;
        }

        if((nRet = SSL_pending(m_pSsl)) > 0)
        {
            uWantRead = nRet;
        }
        else
        {
            uWantRead = 0;
        }
    }

    return uReadCount;

}

