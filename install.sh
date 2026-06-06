#!/usr/bin/env bash
#
# lockbit-rescue install helper
# -----------------------------
# Clones the upstream stream-reuse decryptor, builds it, and installs the
# Python dependencies needed by lockbit-rescue.py / verify-recovered.py.
#
# Usage:   bash install.sh
# Tested:  Linux x86_64; works on Debian/Ubuntu/Arch/CachyOS.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_DIR="${HERE}/_stream-reuse"
UPSTREAM_REPO="https://github.com/yohanes/lockbit-v3-linux-decryptor.git"

echo "[*] lockbit-rescue installer"
echo "    target dir: ${HERE}"

# 1) Check system tools
need() {
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing '$1'. Install it via your package manager."; exit 1; }
}
need git
need make
need gcc
need file
need python3

# 2) Python dep
if ! python3 -c "import tqdm" >/dev/null 2>&1; then
    echo "[*] Installing tqdm (python module)"
    if command -v pipx >/dev/null 2>&1; then
        pipx install tqdm || true
    fi
    pip install --user tqdm || pip3 install --user tqdm || {
        echo "ERROR: could not install tqdm. Run: pip install --user tqdm"
        exit 1
    }
fi

# 3) Clone/update upstream decryptor and build stream-reuse
if [ ! -d "${UPSTREAM_DIR}/.git" ]; then
    echo "[*] Cloning upstream decryptor: ${UPSTREAM_REPO}"
    git clone --depth=1 "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
else
    echo "[*] Updating upstream decryptor"
    git -C "${UPSTREAM_DIR}" pull --ff-only || true
fi

echo "[*] Building stream-reuse"
make -C "${UPSTREAM_DIR}" stream-reuse

# 3b) Build brute_extend2 (pure-C, segfault-free) and direct_decrypt.
# These are our additions on top of upstream; copy our source into the
# upstream clone before building so they have access to frank.h / aplib.h.
if [ -f "${HERE}/src/_brute_extend.c" ]; then
    cp -f "${HERE}/src/_brute_extend.c" "${UPSTREAM_DIR}/brute_extend2.c"
fi
if [ -f "${HERE}/src/_direct_decrypt.c" ]; then
    cp -f "${HERE}/src/_direct_decrypt.c" "${UPSTREAM_DIR}/direct_decrypt.c"
fi

if [ -f "${UPSTREAM_DIR}/brute_extend2.c" ]; then
    echo "[*] Building brute_extend2 (pure-C keystream brute force)"
    gcc -o "${UPSTREAM_DIR}/brute_extend2" "${UPSTREAM_DIR}/brute_extend2.c" \
        "${UPSTREAM_DIR}/aplib.a" -m32 -fno-stack-protector -O2 -D_FILE_OFFSET_BITS=64
fi

if [ -f "${UPSTREAM_DIR}/direct_decrypt.c" ]; then
    echo "[*] Building direct_decrypt (body decrypt from recovered key)"
    gcc -o "${UPSTREAM_DIR}/direct_decrypt" "${UPSTREAM_DIR}/direct_decrypt.c" \
        -m32 -z execstack -fno-stack-protector -no-pie -Wl,-z,norelro -static \
        -O0 -D_FILE_OFFSET_BITS=64
fi

# 4) Symlink so the rescue tools find them next to themselves
ln -sfn "${UPSTREAM_DIR}/stream-reuse"   "${HERE}/stream-reuse"
ln -sfn "${UPSTREAM_DIR}/brute_extend2"  "${HERE}/brute-extend"
ln -sfn "${UPSTREAM_DIR}/direct_decrypt" "${HERE}/direct-decrypt"
chmod +x "${HERE}/stream-reuse" "${HERE}/brute-extend" "${HERE}/direct-decrypt" 2>/dev/null || true

# Stage local copies of brute_extend2.c / direct_decrypt.c for offline reference
cp -f "${UPSTREAM_DIR}/brute_extend2.c" "${HERE}/src/_brute_extend.c" 2>/dev/null || true
cp -f "${UPSTREAM_DIR}/direct_decrypt.c" "${HERE}/src/_direct_decrypt.c" 2>/dev/null || true

# 5) Make our scripts executable
chmod +x "${HERE}/lockbit-rescue.py" "${HERE}/verify-recovered.py" 2>/dev/null || true

echo
echo "[+] Done."
echo "    Binary:  ${HERE}/stream-reuse"
echo
echo "Try it:"
echo "    python3 ${HERE}/lockbit-rescue.py /path/to/encrypted /path/to/output"
