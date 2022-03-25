from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# UI Related
from alive_progress import alive_bar

# Built-in packages
from os import path, SEEK_END, mkdir
from pathlib import Path

# Custom packages
from utils import get_file_size, calculate_file_hash

def _close_file(handler):
    try:
        handler.close()
        print('file_handler closed...')
    except UnboundLocalError:
        print('file_handler was never used, closing not required...')

def generate_key(key_path: str, key_size=2048):
    print(f'generating rsa ({key_size}-bit) key...')
    keys = RSA.generate(key_size)
    if not Path(key_path).exists():
        mkdir(key_path)
    
    print("saving keys...")
    with open(f'{key_path}/key_rsa', 'wb') as f:
        f.write(keys.export_key())
    
    with open(f'{key_path}/key_rsa.pub', 'wb') as f:
        f.write(keys.public_key().export_key())
    
    print(f'keys exported to "{key_path}"')
    return keys

#pylint:disable=not-callable
def encrypt_file(file_path: str, rsa_key: str, chunk_size = 2097152):
    print('getting rsa info...')
    key = RSA.import_key(open(rsa_key).read())

    print('generating random aes key...')
    session_key = get_random_bytes(16)

    try:
        print('getting file information...')
        file_in = open(file_path, 'rb')
        file_size = get_file_size(file_in)
        file_hash = calculate_file_hash(file_in)

        print(f'file hash : {file_hash}')
        print('generating and encrypting keys...')
        cipher_rsa = PKCS1_OAEP.new(key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        print('writing aes information to file...')
        file_out = open(f'{file_path}.enc', 'wb')
        file_out.write(enc_session_key)

        with alive_bar(file_size, title='encryption...') as bar:
            while(data := file_in.read(chunk_size)):
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                file_out.write(cipher_aes.nonce)
                file_out.write(tag)
                file_out.write(ciphertext)
                bar(len(data))
    except KeyboardInterrupt:
        print('encryption interrupted...')

    _close_file(file_in)
    _close_file(file_out)

def decrypt_file(file_path: str, rsa_key: str, chunk_size = 2097152):
    print('getting rsa info...')
    key = RSA.import_key(open(rsa_key).read())
    
    try:
        print('extracting file info...')
        file_in = open(file_path, 'rb')
        file_size = get_file_size(file_in)
        enc_session_key = file_in.read(key.size_in_bytes())

        print('decrypting session key...')
        cipher_rsa = PKCS1_OAEP.new(key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        new_file_path = file_path.removesuffix('.enc')
        file_out = open(new_file_path, 'wb')

        print('decrypting and verifying data...')
        with alive_bar(file_size, title='decrypting...') as bar:
            bar(key.size_in_bytes())
            while(data := file_in.read(chunk_size + 16 + 16)):
                nonce = data[:16]
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                tag = data[16:32]
                ciphertext = data[32:]
                # --------------------
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                file_out.write(data)
                bar(len(nonce) + len(tag) + len(ciphertext))
    except KeyboardInterrupt:
        print('decryption interrupted...')
    except ValueError as e:
        print(e)
    
    _close_file(file_in)
    _close_file(file_out)

