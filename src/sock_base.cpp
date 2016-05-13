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


int Socket::Handshake()
{
    return SOCKET_ERR_NONE;
}

