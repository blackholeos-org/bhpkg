CC = musl-gcc
SYSROOT = $(PWD)/sysroot

CFLAGS = -Wall -Wextra -O3 -flto -march=native -pipe -fstack-protector-strong \
         -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security \
         -Iinclude -I$(SYSROOT)/include -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu \
         -MMD -MP -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
EXEC = bhpkg

SRC = src/main.c src/graph.c src/net.c src/crypto.c src/archive.c src/db.c src/utils.c src/build.c src/hook.c src/version.c
OBJ = $(SRC:.c=.o)
DEP = $(SRC:.c=.d)

LDFLAGS = -static -flto -L$(SYSROOT)/lib -L$(SYSROOT)/lib64 -larchive -lcurl -lzstd -lssl -lcrypto -lsqlite3 -lz -lpthread

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o src/*.d $(EXEC)

-include $(DEP)