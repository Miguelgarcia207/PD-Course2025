import os
import sys
import argparse
import base64
import getpass
import struct
import tarfile
import io
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from hashlib import sha256

BLOCK_SIZE = 16  # AES block size in bytes for AES-CBC


def decrypt_blob(blob, key, output_dir):
    """
    Try to decrypt an entire blob with the given key, writing files into output_dir.
    Returns True on success, False if the blob / key combination looks invalid.
    """
    try:
        # New blob format: salt (16) + nonce (12) + ciphertext + tag (16)
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < 16 + 12 + 16:
            return False

        salt = blob[:16]
        nonce = blob[16:28]
        ct_and_tag = blob[28:]

        # Derive key from caller-provided key (which here is the passphrase-derived key)
        # In this design, caller provides full key bytes. We'll expect key to already be the 32-byte key.
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            tar_bytes = cipher.decrypt_and_verify(ct_and_tag[:-16], ct_and_tag[-16:])
        except Exception:
            return False

        # Try to open the tar archive from memory and extract files
        bio = io.BytesIO(tar_bytes)
        try:
            with tarfile.open(fileobj=bio, mode="r:") as tar:
                members = tar.getmembers()
                if not members:
                    return False
                for member in members:
                    member_path = member.name
                    dest_path = os.path.join(output_dir, member_path)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    if member.isfile():
                        f = tar.extractfile(member)
                        if f is None:
                            return False
                        with open(dest_path, "wb") as out_f:
                            out_f.write(f.read())
        except (tarfile.ReadError, EOFError):
            return False

        return True
    except Exception:
        return False


def empty_directory(path):
    """
    Delete all files and subdirs inside path (but keep path itself).
    WARNING: used here when switching from public to private attempt.
    """
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))


def main():
    parser = argparse.ArgumentParser(description="Decrypt a PD bundle using a passphrase")
    parser.add_argument("bundle_path")
    parser.add_argument("output_dir")
    parser.add_argument("--prompt", action="store_true", help="Prompt for passphrase interactively")
    parser.add_argument("--passphrase", help="Passphrase to use for unlocking (use only if not prompting)")
    args = parser.parse_args()

    bundle_path = args.bundle_path
    output_dir = args.output_dir

    if not os.path.isfile(bundle_path):
        print(f"Error: bundle_file '{bundle_path}' does not exist")
        sys.exit(1)

    # Acquire passphrase
    if args.prompt:
        passphrase = getpass.getpass("Passphrase: ")
    elif args.passphrase:
        passphrase = args.passphrase
    else:
        # default to prompt
        passphrase = getpass.getpass("Passphrase: ")

    os.makedirs(output_dir, exist_ok=True)

    # The header may be obfuscated by a random prefix. Scan the first 64KB for a valid header.
    max_scan = 65536
    file_size = os.path.getsize(bundle_path)
    public_blob = None
    private_blob = None

    with open(bundle_path, "rb") as f:
        found = False
        scan_limit = min(max_scan, file_size - 8)
        for offset in range(0, scan_limit + 1):
            f.seek(offset)
            header = f.read(8)
            if len(header) != 8:
                continue
            public_len = struct.unpack(">Q", header)[0]
            public_start = offset + 8
            public_end = public_start + public_len
            if public_end > file_size:
                continue
            # tentatively read the two blobs
            f.seek(public_start)
            candidate_public = f.read(public_len)
            f.seek(public_end)
            candidate_private = f.read()

            # Quick sanity: candidate_public must be at least 16 bytes for salt
            if not isinstance(candidate_public, (bytes, bytearray)) or len(candidate_public) < 16:
                continue

            # Try to derive key and decrypt using the provided passphrase for the public blob
            pub_salt = candidate_public[:16]
            key_try = derive_key_from_passphrase(passphrase, pub_salt)
            if decrypt_blob(candidate_public, key_try, output_dir):
                public_blob = candidate_public
                private_blob = candidate_private
                found = True
                break

        if not found:
            # If header not found, attempt fallback: try reading header at start (legacy)
            f.seek(0)
            header = f.read(8)
            if len(header) == 8:
                public_len = struct.unpack(">Q", header)[0]
                public_blob = f.read(public_len)
                private_blob = f.read()
            else:
                print("Error: bundle file too short / invalid header")
                sys.exit(1)

    def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 200000) -> bytes:
        return PBKDF2(passphrase.encode('utf-8'), salt, dkLen=32, count=iterations, hmac_hash_module=sha256)

    # First try to decrypt as the public volume
    if isinstance(public_blob, (bytes, bytearray)) and len(public_blob) >= 16:
        pub_salt = public_blob[:16]
        key = derive_key_from_passphrase(passphrase, pub_salt)
        if decrypt_blob(public_blob, key, output_dir):
            print("Decryption successful (public volume).")
            sys.exit(0)
    else:
        # public blob invalid size; skip
        pass

    # If that failed, clear whatever got written and try the private volume
    empty_directory(output_dir)

    if isinstance(private_blob, (bytes, bytearray)) and len(private_blob) >= 16:
        priv_salt = private_blob[:16]
        priv_key = derive_key_from_passphrase(passphrase, priv_salt)
        if decrypt_blob(private_blob, priv_key, output_dir):
            print("Decryption successful (hidden volume).")
            sys.exit(0)


    print("Decryption failed: key did not match any volume.")
    sys.exit(1)


if __name__ == "__main__":
    main()
