#include "sock_base.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <error.h>
#include <assert.h>

Socket::Socket(int fd)
    :m_fd(fd)
#ifdef HAS_OPENSSL
    ,m_pSsl(NULL)
#endif
{

}

Socket::~Socket()
{
    Close();
}

void Socket::Close()
{
    close(m_fd);
}

