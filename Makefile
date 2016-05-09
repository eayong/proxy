TARGET = proxy

OUT_DIR = ./bin
 
$(shell if [ ! -d $(OUT_DIR) ]; then mkdir $(OUT_DIR) -p;fi;)

INCLUDE_DIR = ./include
LIBEVENT_INC = ./include/libevent

OBJECTS += ./src/main.o
OBJECTS += ./src/proxy.o
OBJECTS += ./src/sock_base.o
OBJECTS += ./src/sock_client.o
OBJECTS += ./src/sock_server.o
OBJECTS += ./src/sock_ssl.o
OBJECTS += ./src/sock_tcp.o
OBJECTS += ./src/ssl_context.o

LIB_DIR = ./lib

ifeq ($(no_debug), 1)
	COMPTYPE = -O2
else
 	COMPTYPE = -g -rdynamic
endif


COMPILER = g++
LINKER   = g++

CFLAGS = -c -D__LINUX -D_REENTRANT -D_GNU_SOURCE -D__STDC_FORMAT_MACROS -DHAS_OPENSSL

$(TARGET) : $(OBJECTS)
	$(LINKER) $(OBJECTS) $(COMPTYPE) -o $(OUT_DIR)/$(TARGET) -L$(LIB_DIR) -ldl -lrt $(LIB_DIR)/libevent.a $(LIB_DIR)/libssl.a $(LIB_DIR)/libcrypto.a

.SUFFIXES:
.SUFFIXES: .c .o .cpp

.cpp.o:
	$(COMPILER) -o $*.o $(COMPTYPE) $(CFLAGS)  -I$(INCLUDE_DIR) -I$(LIBEVENT_INC) $*.cpp

.c.o:
	$(COMPILER) -o $*.o $(COMPTYPE) $(CFLAGS)  -I$(INCLUDE_DIR) -I$(LIBEVENT_INC) $*.c
	

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -rf $(OUT_DIR)/*
	
