import os
import sys
import pickle
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16  # AES block size in bytes for AES-CBC


def encrypt_directory(dir_path, key):
    """
    Walk dir_path and return a dict:
        {relative_path: iv + ciphertext}
    """
    dir_path = os.path.abspath(dir_path)
    encrypted = {}

    for root, _, files in os.walk(dir_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, dir_path)

            with open(full_path, "rb") as f:
                plaintext = f.read()

            iv = get_random_bytes(BLOCK_SIZE)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))

            encrypted[rel_path] = iv + ciphertext

    return encrypted


def main():
    if len(sys.argv) != 4:
        print("Usage: python PD-encrypt.py <public_dir> <private_dir> <output_bundle>")
        sys.exit(1)

    public_dir = sys.argv[1]
    private_dir = sys.argv[2]
    bundle_path = sys.argv[3]

    if not os.path.isdir(public_dir):
        print(f"Error: public_dir '{public_dir}' is not a directory")
        sys.exit(1)
    if not os.path.isdir(private_dir):
        print(f"Error: private_dir '{private_dir}' is not a directory")
        sys.exit(1)

    # Generate two independent 32-byte (256-bit) keys
    public_key = get_random_bytes(32)
    private_key = get_random_bytes(32)

    print("Generated keys:")
    print("  public.key")
    print("  private.key")

    # Save keys as raw bytes (demo only – in a real system you'd derive from passwords)
    with open("public.key", "wb") as f:
        f.write(public_key)
    with open("private.key", "wb") as f:
        f.write(private_key)

    # Encrypt both directories
    public_dict = encrypt_directory(public_dir, public_key)
    private_dict = encrypt_directory(private_dir, private_key)

    public_blob = pickle.dumps(public_dict, protocol=pickle.HIGHEST_PROTOCOL)
    private_blob = pickle.dumps(private_dict, protocol=pickle.HIGHEST_PROTOCOL)

    # Write bundle: [8-byte big-endian length][public_blob][private_blob]
    public_len = len(public_blob)
    header = struct.pack(">Q", public_len)

    with open(bundle_path, "wb") as out:
        out.write(header)
        out.write(public_blob)
        out.write(private_blob)

    print(f"Bundle written to {bundle_path}")
    print("Keep the .key files safe and distribute only the appropriate one to each user.")


if __name__ == "__main__":
    main()
