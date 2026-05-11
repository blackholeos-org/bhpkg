#!/usr/bin/env python3
import os
import subprocess
import tarfile
import requests
import re
import shlex
from pathlib import Path

# config
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

ENV["PKG_CONFIG_LIBDIR"] = f"{SYSROOT_STR}/lib/pkgconfig:{SYSROOT_STR}/share/pkgconfig"
ENV["PKG_CONFIG_PATH"] = ""

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

def github_release_asset(repo, keyword):
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    r = requests.get(api, timeout=15)
    r.raise_for_status()
    data = r.json()
    
    for asset in data.get("assets",[]):
        if keyword in asset["name"] and asset["name"].endswith(".tar.gz"):
            return asset["browser_download_url"]
            
    return data["tarball_url"]

def scrape_sqlite():
    try:
        html = requests.get("https://www.sqlite.org/download.html", timeout=15).text
        match = re.search(r"(\d{4}/sqlite-autoconf-\d+\.tar\.gz)", html)
        if match:
            return f"https://www.sqlite.org/{match.group(1)}"
    except Exception as e:
        log(f"Warning: SQLite scrape failed ({e})")
    return "https://www.sqlite.org/2026/sqlite-autoconf-3530100.tar.gz"

def scrape_curl():
    try:
        html = requests.get("https://curl.se/download.html", timeout=15).text
        match = re.search(r"curl-([\d.]+)\.tar\.gz", html)
        if match:
            return f"https://curl.se/download/curl-{match.group(1)}.tar.gz"
    except Exception as e:
        log(f"Warning: cURL scrape failed ({e})")
    return "https://curl.se/download/curl-8.20.0.tar.gz"

def build_zlib():
    if is_done("zlib"): return
    log("Building zlib")
    tar = fetch("https://zlib.net/current/zlib.tar.gz", "zlib.tar.gz")
    src = extract(tar)

    run(f"./configure --static --prefix={SYSROOT_STR}", cwd=src)
    run(f"make -j{JOBS}", cwd=src)
    run("make install", cwd=src)
    mark_done("zlib")

def build_openssl():
    if is_done("openssl"): return
    log("Building OpenSSL")
    url = github_release_asset("openssl/openssl", "openssl")
    tar = fetch(url, "openssl.tar.gz")
    src = extract(tar)

    run(f"./Configure no-shared no-async no-secure-memory linux-x86_64 --prefix={SYSROOT_STR}", cwd=src)
    run(f"make -j{JOBS}", cwd=src)
    run("make install_sw", cwd=src)
    mark_done("openssl")

def build_zstd():
    if is_done("zstd"): return
    log("Building zstd")
    url = github_release_asset("facebook/zstd", "zstd")
    tar = fetch(url, "zstd.tar.gz")
    src = extract(tar)

    run(f"make lib-mt -j{JOBS}", cwd=src)
    run(f"make -C lib PREFIX={SYSROOT_STR} install", cwd=src)
    
    for so_file in (SYSROOT / "lib").glob("*.so*"):
        so_file.unlink(missing_ok=True)
    mark_done("zstd")

def build_sqlite():
    if is_done("sqlite"): return
    log("Building SQLite")
    url = scrape_sqlite()
    tar = fetch(url, "sqlite.tar.gz")
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
    url = scrape_curl()
    tar = fetch(url, "curl.tar.gz")
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
    url = github_release_asset("libarchive/libarchive", "libarchive")
    tar = fetch(url, "libarchive.tar.gz")
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
        f"--with-zstd --with-zlib "
        f"--prefix={SYSROOT_STR}",
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
    print(" [+] Sysroot build complete (Python)")
    print("====================================")

if __name__ == "__main__":
    main()