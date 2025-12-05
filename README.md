concrete order:

Step 1 – Add a proper README (so your repo looks real)

Open README.md in VS Code and replace its contents with something like this:

# Plausibly-Deniable Encrypted Storage (Prototype 1)

This project implements a simple *classic decoy model* for plausibly-deniable storage:
a single encrypted bundle file contains two separate encrypted directory trees:
- a **public (decoy)** directory
- a **private (hidden)** directory

Depending on which key is used, the decryptor recovers either the public or hidden files.

## Requirements

- Python 3.9+
- [PyCryptodome](https://pycryptodome.readthedocs.io/)

To install dependencies in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate           # on macOS / Linux
pip install pycryptodome

Files:

PD-encrypt.py – packs a public and private directory into a single encrypted bundle.

PD-decrypt.py – given the bundle and a key, recovers either the public or hidden directory.

public_dir/ – example public (decoy) directory (for testing).

private_dir/ – example hidden directory (for testing).

Usage:
1. Create example directories (optional demo)
mkdir public_dir private_dir
echo "this is public"  > public_dir/public.txt
echo "this is secret"  > private_dir/secret.txt

2. Encrypt into a bundle
python3 PD-encrypt.py public_dir private_dir bundle.bin


This generates:

bundle.bin – the encrypted container file

public.key – 32-byte key for the public (decoy) volume

private.key – 32-byte key for the hidden volume

3. Decrypt the public (decoy) volume
mkdir -p out_public
python3 PD-decrypt.py bundle.bin public.key out_public


Recovered files will appear under out_public/.

4. Decrypt the hidden volume
mkdir -p out_private
python3 PD-decrypt.py bundle.bin private.key out_private


Recovered files will appear under out_private/.

Notes / Limitations

Keys are randomly generated 32-byte values and stored as raw .key files (demo only).

The bundle file format is:

[8-byte big-endian length of public blob][public blob][private blob]


Each file is encrypted with AES-256 in CBC mode with a fresh random IV.

Future work (Prototype 2) will explore an obfuscation-based design and password-based key
derivation (e.g., scrypt) instead of raw keys, as well as improved resistance to forensic tools.


Save that.

Then in your terminal:

```bash
git status
git add PD-encrypt.py PD-decrypt.py README.md
git commit -m "Add working Prototype 1 with README"
git push