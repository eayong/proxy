#ifndef __PROXY_SOCK_BASE_H__
#define __PROXY_SOCK_BASE_H__

#ifdef HAS_OPENSSL
#include <ssl_context.h>
#endif // HAS_OPENSSL

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

class Socket
{
public:
    Socket(int fd);
    virtual ~Socket();

public:
    virtual int Send(const char *data, uint32_t len) = 0;
    virtual int Recv(char *data, uint32_t len) = 0;
    void Close();

    int GetFd() { return m_fd; }

#ifdef HAS_OPENSSL
    SSL *GetSsl() { return m_pSsl; }
#endif // HAS_OPENSSL

protected:
    int     m_fd;
#ifdef HAS_OPENSSL
    SSL     *m_pSsl;
#endif // HAS_OPENSSL
};


#endif // __PROXY_SOCK_BASE_H__

