CC = musl-gcc
SYSROOT = $(PWD)/sysroot

CFLAGS = -Wall -Wextra -O3 -Iinclude -I$(SYSROOT)/include -MMD -MP -D_GNU_SOURCE
EXEC = bhpkg

SRC = src/main.c src/graph.c src/net.c src/crypto.c src/archive.c src/db.c src/build.c src/utils.c
OBJ = $(SRC:.c=.o)
DEP = $(SRC:.c=.d)

LDFLAGS = -static -L$(SYSROOT)/lib -L$(SYSROOT)/lib64 -larchive -lcurl -lzstd -lssl -lcrypto -lsqlite3 -lz -lpthread

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o src/*.d $(EXEC)

-include $(DEP)