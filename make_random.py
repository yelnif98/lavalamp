#This code was entirely generated from ChatGPT

#!/usr/bin/env python3
"""
make_random.py

Reads SHA-256 hex-digests from frame_hashes.txt (one per line), pairs them up,
then for each pair:

  1) Concatenates the two 32-byte seeds → 64 bytes total
  2) Instantiates HMAC-DRBG with that 512 bit seed
  3) Generates BYTES_PER_CHUNK bytes, in sub-calls of ≤ MAX_BYTES_PER_GEN bytes
  4) Appends that to random.bin

"""

from pathlib import Path
from hmac_drbg import HMAC_DRBG

HASH_FILE         = Path("frame_hashes.txt")
OUTPUT_FILE       = Path("random.bin")

# ─── tunables ─────────────────────────────────────────────────────────────

# how many pseudo-random bytes per *pair* of frames?
BYTES_PER_CHUNK   = 64 * 1024       #  1 KiB per pair → ~500 KiB total for ~1 000 frames

# python-hmac-drbg can only do up to 7 500 bits (~937 bytes) per generate()
MAX_BITS_PER_GEN  = 7500
MAX_BYTES_PER_GEN = MAX_BITS_PER_GEN // 8  # = 937

# ─── driver ──────────────────────────────────────────────────────────────

def main():
    # read in & clean up all 64-char hex-strings
    lines = HASH_FILE.read_text().splitlines()
    hexes = [h.strip() for h in lines if h.strip()]

    # if odd number, drop the last one
    if len(hexes) % 2:
        hexes = hexes[:-1]

    # pair them (0+1), (2+3), …
    seeds = list(zip(hexes[0::2], hexes[1::2]))
    total = len(seeds)

    # open output file once in binary mode
    with OUTPUT_FILE.open("wb") as out:
        for idx, (h1, h2) in enumerate(seeds, start=1):
            # build the 64-byte seed
            seed_bytes = bytes.fromhex(h1 + h2)

            # instantiate with full 512 bit seed
            drbg = HMAC_DRBG(
                entropy=seed_bytes,
                requested_security_strength=256,
                personalization_string=b""
            )

            # emit BYTES_PER_CHUNK, in ≤ MAX_BYTES_PER_GEN‐byte generate() calls
            remaining = BYTES_PER_CHUNK
            written   = 0
            while remaining > 0:
                to_gen = min(remaining, MAX_BYTES_PER_GEN)
                block  = drbg.generate(to_gen)
                out.write(block)
                remaining -= to_gen
                written   += to_gen

            print(f"[{idx}/{total}] wrote {written} bytes")

    final_size = OUTPUT_FILE.stat().st_size
    print(f"Done – total size: {final_size} bytes → {final_size/1024:.1f} KiB")


if __name__ == "__main__":
    main()
