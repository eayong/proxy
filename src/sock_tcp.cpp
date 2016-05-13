#include "sock_tcp.h"

TcpSocket::TcpSocket(int fd, int type)
    : Socket(fd, type)
{
    
}

TcpSocket::~TcpSocket()
{

}

int TcpSocket::Send(const char * data, uint32_t len)
{
    return 0;
}

int TcpSocket::Recv(char * data, uint32_t len)
{

    return 0;
}

