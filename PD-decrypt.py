import os
import sys
import pickle
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16  # AES block size in bytes for AES-CBC


def decrypt_blob(blob, key, output_dir):
    """
    Try to decrypt an entire blob with the given key, writing files into output_dir.
    Returns True on success, False if the blob / key combination looks invalid.
    """
    try:
        file_dict = pickle.loads(blob)
        if not isinstance(file_dict, dict):
            return False

        for rel_path, iv_cipher in file_dict.items():
            if not isinstance(rel_path, str):
                return False
            if not isinstance(iv_cipher, (bytes, bytearray)) or len(iv_cipher) < BLOCK_SIZE:
                return False

            iv = iv_cipher[:BLOCK_SIZE]
            ciphertext = iv_cipher[BLOCK_SIZE:]

            from Crypto.Cipher import AES  # local import to avoid circulars if any
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext_padded = cipher.decrypt(ciphertext)
            plaintext = unpad(plaintext_padded, BLOCK_SIZE)

            out_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(plaintext)

        return True
    except Exception:
        # Any error is treated as "wrong key"
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
    if len(sys.argv) != 4:
        print("Usage: python PD-decrypt.py <bundle_file> <key_file> <output_dir>")
        sys.exit(1)

    bundle_path = sys.argv[1]
    key_path = sys.argv[2]
    output_dir = sys.argv[3]

    if not os.path.isfile(bundle_path):
        print(f"Error: bundle_file '{bundle_path}' does not exist")
        sys.exit(1)
    if not os.path.isfile(key_path):
        print(f"Error: key_file '{key_path}' does not exist")
        sys.exit(1)

    with open(key_path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        print("Error: key must be 32 bytes (256 bits)")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    with open(bundle_path, "rb") as f:
        header = f.read(8)
        if len(header) != 8:
            print("Error: bundle file too short / invalid header")
            sys.exit(1)
        public_len = struct.unpack(">Q", header)[0]
        public_blob = f.read(public_len)
        private_blob = f.read()

    # First try to decrypt as the public volume
    if decrypt_blob(public_blob, key, output_dir):
        print("Decryption successful (public volume).")
        sys.exit(0)

    # If that failed, clear whatever got written and try the private volume
    empty_directory(output_dir)

    if decrypt_blob(private_blob, key, output_dir):
        print("Decryption successful (hidden volume).")
        sys.exit(0)

    print("Decryption failed: key did not match any volume.")
    sys.exit(1)


if __name__ == "__main__":
    main()
