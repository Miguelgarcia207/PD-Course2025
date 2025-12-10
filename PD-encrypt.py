import argparse
import base64
import os
import sys
import struct
import tarfile
import io
import getpass
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16  # AES block size in bytes for AES-CBC


def pack_directory_to_tar_bytes(dir_path):
    """Create an in-memory tar archive of `dir_path` and return bytes."""
    dir_path = os.path.abspath(dir_path)
    bio = io.BytesIO()
    # use gz compression? keep raw tar to avoid leaking compression headers
    with tarfile.open(fileobj=bio, mode="w") as tar:
        for root, _, files in os.walk(dir_path):
            for filename in files:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, dir_path)
                tar.add(full_path, arcname=rel_path)
    return bio.getvalue()


def encrypt_tar_bytes(tar_bytes, key):
    """Encrypt tar_bytes with AES-GCM using `key`.

    Returns: salt (16) + nonce (12) + ciphertext + tag (16)
    """
    # AES-GCM nonce 12 bytes recommended
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(tar_bytes)
    return nonce + ciphertext + tag


def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 200000) -> bytes:
    # PBKDF2-HMAC-SHA256
    return PBKDF2(passphrase.encode('utf-8'), salt, dkLen=32, count=iterations, hmac_hash_module=sha256)


def generate_passphrase(nbytes: int = 24) -> str:
    return base64.urlsafe_b64encode(get_random_bytes(nbytes)).decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description="Create a plausibly-deniable encrypted bundle.")
    parser.add_argument("public_dir")
    parser.add_argument("private_dir")
    parser.add_argument("bundle_path")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--prompt", action="store_true", help="Prompt for two passphrases interactively")
    group.add_argument("--generate", action="store_true", help="Generate two random passphrases and display them once")
    args = parser.parse_args()

    public_dir = args.public_dir
    private_dir = args.private_dir
    bundle_path = args.bundle_path

    if not os.path.isdir(public_dir):
        print(f"Error: public_dir '{public_dir}' is not a directory")
        sys.exit(1)
    if not os.path.isdir(private_dir):
        print(f"Error: private_dir '{private_dir}' is not a directory")
        sys.exit(1)

    # Obtain or generate passphrases; derive keys with PBKDF2 and random salts.
    if args.generate:
        pub_pass = generate_passphrase()
        priv_pass = generate_passphrase()
        print("Generated passphrases (SAVE THESE NOW, they are shown only once):")
        print("public:", pub_pass)
        print("private:", priv_pass)
    elif args.prompt:
        pub_pass = getpass.getpass("Enter public passphrase: ")
        pub_pass_confirm = getpass.getpass("Confirm public passphrase: ")
        if pub_pass != pub_pass_confirm:
            print("Public passphrases do not match")
            sys.exit(1)
        priv_pass = getpass.getpass("Enter private passphrase: ")
        priv_pass_confirm = getpass.getpass("Confirm private passphrase: ")
        if priv_pass != priv_pass_confirm:
            print("Private passphrases do not match")
            sys.exit(1)
    else:
        # default: prompt interactively
        pub_pass = getpass.getpass("Enter public passphrase: ")
        priv_pass = getpass.getpass("Enter private passphrase: ")

    # Pack both directories into tar bytes
    public_tar = pack_directory_to_tar_bytes(public_dir)
    private_tar = pack_directory_to_tar_bytes(private_dir)

    # For each volume, create a random salt and derive key, then encrypt using AES-GCM
    public_salt = get_random_bytes(16)
    private_salt = get_random_bytes(16)

    public_key = derive_key_from_passphrase(pub_pass, public_salt)
    private_key = derive_key_from_passphrase(priv_pass, private_salt)

    public_encrypted = encrypt_tar_bytes(public_tar, public_key)
    private_encrypted = encrypt_tar_bytes(private_tar, private_key)

    # Blob format for each volume: salt (16) + nonce (12) + ciphertext + tag (16)
    public_blob = public_salt + public_encrypted
    private_blob = private_salt + private_encrypted

    # Write bundle: [8-byte big-endian length][public_blob][private_blob]
    public_len = len(public_blob)
    header = struct.pack(">Q", public_len)

    # Obfuscate header by prepending a random prefix of variable length
    prefix_len = int.from_bytes(get_random_bytes(2), "big")
    # stretch into a range [4KB, 64KB]
    prefix_len = 4096 + (prefix_len % (65536 - 4096))
    prefix = get_random_bytes(prefix_len)

    with open(bundle_path, "wb") as out:
        out.write(prefix)
        out.write(header)
        out.write(public_blob)
        out.write(private_blob)

    print(f"Bundle written to {bundle_path}")
    print("Bundle written to {}".format(bundle_path))
    print("Keep the passphrases safe and distribute only the appropriate one to each user.")


if __name__ == "__main__":
    main()
