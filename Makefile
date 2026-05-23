.PHONY: all clean bhpkg

TARGET = x86_64-unknown-linux-musl

export CC_x86_64_unknown_linux_musl = musl-gcc
export CXX_x86_64_unknown_linux_musl = musl-g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = -C target-feature=+crt-static -C relocation-model=static
export PKG_CONFIG = /bin/false
export LIBCURL_NO_PKG_CONFIG = 1

all: bhpkg

bhpkg:
	@echo "[*] Building bhpkg via Cargo (Native)..."
	cargo build --release --target $(TARGET)
	cp target/$(TARGET)/release/bhpkg ./bhpkg

clean:
	@echo "[*] Cleaning Cargo cache..."
	cargo clean
	rm -f bhpkg