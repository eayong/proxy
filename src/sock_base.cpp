#include "sock_base.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <error.h>
#include <assert.h>

Socket::Socket(int fd, int type)
    :m_fd(fd), m_type(type), m_status(SOCKET_INVALID)
#ifdef HAS_OPENSSL
    ,m_pSsl(NULL)
#endif
{
    InitAddr();
}

Socket::~Socket()
{
    Close();
    m_status = SOCKET_INVALID;
}


int Socket::SetNonBlocking(bool blocking)
{
    int flags;
    if ((flags = fcntl(m_fd, F_GETFL, 0)) == -1)
    {
        flags = 0;
    }
    if (blocking)
    {
        flags |= O_NONBLOCK;
    }
    else
    {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(m_fd, F_SETFL, flags);
}

int Socket::SetTimeout(int sec)
{
    struct timeval timeout={sec, 0};
    
    int ret = setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    if (ret != 0)
    {
        return -1;
    }
    ret = setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    if (ret != 0)
    {
        return -1;
    }
    return 0;
}

int Socket::Handshake()
{
    return SOCKET_ERR_NONE;
}

int Socket::InitAddr()
{
    socklen_t  len = sizeof(struct sockaddr_in);
    if (getsockname(m_fd, (struct sockaddr*)&m_localAddr, &len ) < 0)
    {
        return -1;
    }
    if (getpeername(m_fd, (struct sockaddr*)&m_remoteAddr, &len ) < 0)
    {
        return -1;
    }
    return 0;
}
