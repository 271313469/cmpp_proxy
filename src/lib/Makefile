TARGET  = libcmpp.a
SRC     = common.c cmpp_proto.c 
OBJ     = $(SRC:.c=.o)
DEFS    = -D_REENTRANT  -D_POSIX_PTHREAD_SEMANTICS -D_GNU_SOURCE -D_DEBUG
INC     = -I./
CFLAGS  = -g -Wall -fPIC $(INC) $(DEFS) 
SHARED  = -shared -o

${TARGET}: ${OBJ}
	ar crv ${TARGET} ${OBJ}
${OBJ}: ${SRC}
	gcc ${CFLAGS} -c ${SRC}
clean:
	rm -f core ${TARGET} ${OBJ}
