#!/usr/bin/env python3
import os
import subprocess
import tarfile
import requests
import shlex
from pathlib import Path

ROOT = Path.cwd()
SYSROOT = ROOT / "sysroot"
BUILD_DIR = ROOT / "build_deps"
CACHE_DIR = ROOT / "cache"
STAMP_DIR = SYSROOT / ".built"

JOBS = os.cpu_count() or 1

for d in [SYSROOT, BUILD_DIR, CACHE_DIR, STAMP_DIR]:
    d.mkdir(parents=True, exist_ok=True)

SYSROOT_STR = str(SYSROOT.resolve())

ENV = os.environ.copy()
ENV["CC"] = "musl-gcc"
ENV["CFLAGS"] = "-O3 -flto -march=native -pipe -fPIE -fstack-protector-strong"
ENV["PKG_CONFIG_LIBDIR"] = f"{SYSROOT_STR}/lib/pkgconfig:{SYSROOT_STR}/share/pkgconfig"
ENV["PKG_CONFIG_PATH"] = ""

ZLIB_URL = "https://zlib.net/fossils/zlib-1.3.2.tar.gz"
OPENSSL_URL = "https://github.com/openssl/openssl/releases/download/openssl-4.0.0/openssl-4.0.0.tar.gz"
ZSTD_URL = "https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz"
SQLITE_URL = "https://www.sqlite.org/2026/sqlite-src-3530100.zip"
CURL_URL = "https://curl.se/download/curl-8.20.0.tar.gz"
LIBARCHIVE_URL = "https://github.com/libarchive/libarchive/releases/download/v3.8.7/libarchive-3.8.7.tar.gz"

def log(msg):
    print(f"[*] {msg}")

def run(cmd, cwd=None, env=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    subprocess.run(cmd, shell=False, check=True, cwd=cwd, env=env or ENV)

def fetch(url, name):
    path = CACHE_DIR / name
    if path.exists():
        log(f"Using cached {name}")
        return path

    log(f"Downloading {name}...")
    with requests.get(url, stream=True, timeout=30) as r:
        r.raise_for_status()
        total = int(r.headers.get('content-length', 0))
        downloaded = 0
        with open(path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        done = int(50 * downloaded / total)
                        print(f"\r[{'#' * done}{'.' * (50-done)}] {downloaded//1024}/{total//1024} KB", end="", flush=True)
                    else:
                        print(f"\r    {downloaded//1024} KB downloaded...", end="", flush=True)
        print() 
    return path

def extract(tar_path: Path):
    with tarfile.open(tar_path) as tar:
        members = tar.getmembers()
        root = None
        for m in members:
            if m.name == "pax_global_header":
                continue
            root = m.name.split("/")[0]
            break
            
        if not root:
            raise ValueError(f"Could not determine root directory from {tar_path.name}")

        out_dir = BUILD_DIR / root
        if out_dir.exists():
            log(f"Already extracted: {root}")
            return out_dir

        log(f"Extracting {tar_path.name}")
        if hasattr(tarfile, "data_filter"):
            tar.extractall(path=BUILD_DIR, filter="data")
        else:
            tar.extractall(path=BUILD_DIR)
            
        return out_dir

def is_done(name):
    return (STAMP_DIR / name).exists()

def mark_done(name):
    (STAMP_DIR / name).touch()

def build_zlib():
    if is_done("zlib"): return
    log("Building zlib")
    tar = fetch(ZLIB_URL, "zlib.tar.gz")
    src = extract(tar)
    run(f"./configure --static --prefix={SYSROOT_STR}", cwd=src)
    run(f"make -j{JOBS}", cwd=src)
    run("make install", cwd=src)
    mark_done("zlib")

def build_openssl():
    if is_done("openssl"): return
    log("Building OpenSSL")
    tar = fetch(OPENSSL_URL, "openssl.tar.gz")
    src = extract(tar)
    run(f"./Configure no-shared no-async no-secure-memory linux-x86_64 --prefix={SYSROOT_STR}", cwd=src)
    run(f"make -j{JOBS}", cwd=src)
    run("make install_sw", cwd=src)
    mark_done("openssl")

def build_zstd():
    if is_done("zstd"): return
    log("Building zstd")
    tar = fetch(ZSTD_URL, "zstd.tar.gz")
    src = extract(tar)
    run(f"make lib-mt -j{JOBS}", cwd=src)
    run(f"make -C lib PREFIX={SYSROOT_STR} install", cwd=src)
    for so_file in (SYSROOT / "lib").glob("*.so*"):
        so_file.unlink(missing_ok=True)
    mark_done("zstd")

def build_sqlite():
    if is_done("sqlite"): return
    log("Building SQLite")
    tar = fetch(SQLITE_URL, "sqlite.tar.gz")
    src = extract(tar)
    env = ENV.copy()
    env["LDFLAGS"] = f"-L{SYSROOT_STR}/lib -static"
    env["LIBS"] = "-pthread"
    run(f"./configure --enable-static --disable-shared --prefix={SYSROOT_STR}", cwd=src, env=env)
    run(f"make -j{JOBS}", cwd=src)
    run("make install", cwd=src)
    mark_done("sqlite")

def build_curl():
    if is_done("curl"): return
    log("Building curl")
    tar = fetch(CURL_URL, "curl.tar.gz")
    src = extract(tar)
    env = ENV.copy()
    env["CPPFLAGS"] = f"-I{SYSROOT_STR}/include"
    env["LDFLAGS"] = f"-L{SYSROOT_STR}/lib -static"
    env["LIBS"] = "-pthread"
    env["PKG_CONFIG"] = "pkg-config --static"
    run(
        f"./configure --enable-static --disable-shared --with-openssl={SYSROOT_STR} "
        f"--prefix={SYSROOT_STR} --without-libidn2 --without-brotli "
        f"--without-zstd --without-libpsl --disable-ldap --disable-ldaps",
        cwd=src, env=env
    )
    run(f"make -j{JOBS}", cwd=src)
    run("make install", cwd=src)
    mark_done("curl")

def build_libarchive():
    if is_done("libarchive"): return
    log("Building libarchive")
    tar = fetch(LIBARCHIVE_URL, "libarchive.tar.gz")
    src = extract(tar)
    env = ENV.copy()
    env["CPPFLAGS"] = f"-I{SYSROOT_STR}/include"
    env["LDFLAGS"] = f"-L{SYSROOT_STR}/lib -static"
    env["LIBS"] = "-pthread"
    env["PKG_CONFIG"] = "pkg-config --static"
    run(
        f"./configure --enable-static --disable-shared "
        f"--without-xml2 --without-expat --without-nettle --without-iconv "
        f"--without-openssl --without-cng --without-lzma --without-bzip2 "
        f"--with-zstd --with-zlib --prefix={SYSROOT_STR}",
        cwd=src, env=env
    )
    run(f"make -j{JOBS}", cwd=src)
    run("make install", cwd=src)
    mark_done("libarchive")

def main():
    build_zlib()
    build_openssl()
    build_zstd()
    build_sqlite()
    build_curl()
    build_libarchive()
    print("\n====================================")
    print(" Sysroot build complete")
    print("====================================")

if __name__ == "__main__":
    main()