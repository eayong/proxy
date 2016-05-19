#ifndef __PROXY_SOCK_BASE_H__
#define __PROXY_SOCK_BASE_H__

#ifdef HAS_OPENSSL
#include <ssl_context.h>
#endif // HAS_OPENSSL

#ifdef HAS_LIBEVENT
#include <event.h>
#endif // HAS_LIBEVENT

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

enum SocketStatus
{
    SOCKET_INVALID,
    SOCKET_HANDSHARE,
    SOCKET_HANDSHARE_SSL,
    SOCKET_CONNECTED,
};

enum SocketType
{
    SOCKET_TCP_CLIENT,
    SOCKET_TCP_SERVER,
    SOCKET_SSL_CLIENT,
    SOCKET_SSL_SERVER,
};

enum SocketErrorCode
{
    SOCKET_ERR_NONE = 0,
    SOCKET_ERR_BLOCK,
    SOCKET_ERR_CLOSE,
    SOCKET_ERR_FAIL,
    SOCKET_ERR_SSL,
};

class Socket
{
public:
    Socket(int fd, int type);
    virtual ~Socket();

public:
    virtual int Send(const char *data, uint32_t len) = 0;
    virtual int Recv(char *data, uint32_t len) = 0;
    virtual int Handshake();
    void SetStatus(SocketStatus status) { m_status = status; }
    void Close() { close(m_fd); m_fd = -1; }
    int SetNonBlocking(bool blocking = true);
    int SetTimeout(int sec);
    int GetFd() { return m_fd; }
    bool IsValibe() { return m_status == SOCKET_CONNECTED; }

    struct sockaddr_in & GetLocalAddr() { return m_localAddr; }
    struct sockaddr_in & GetRemoteAddr() { return m_remoteAddr; }

#ifdef HAS_OPENSSL
    SSL *GetSsl() { return m_pSsl; }
#endif // HAS_OPENSSL

#ifdef HAS_LIBEVENT
    struct event &GetEvent() { return m_ev; }
#endif // HAS_LIBEVENT

private:
    int InitAddr();

protected:
    int                 m_fd;
    int                 m_type;
    SocketStatus        m_status;
    struct sockaddr_in  m_localAddr;
    struct sockaddr_in  m_remoteAddr;
    
#ifdef HAS_OPENSSL
    SSL     *m_pSsl;
#endif // HAS_OPENSSL

#ifdef HAS_LIBEVENT
    struct event m_ev;
#endif // HAS_LIBEVENT
};


#endif // __PROXY_SOCK_BASE_H__

