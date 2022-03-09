import chunk
from genericpath import isdir
from threading import get_ident
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from pathlib import Path
from os import getcwd, mkdir, path, SEEK_END
from alive_progress import alive_bar

import argparse

from isort import file

# TODO :
## Clean up the code, possible separate it.

home_dir = Path.home().__str__()
key_path = f"{home_dir}/.keys"

decrypt = False # 0 - decrypt | 1 - encrypt

# --- dev related info ---
dev_mode = 1
if(dev_mode == 1):
    exec_path = getcwd()
    enc_path = f'{exec_path}/encrypt'
    dec_path = f'{exec_path}/decrypt'
    key_path = f'{exec_path}/.keys'

def setup_parser():
    parser = argparse.ArgumentParser(description="figure it out")
    parser.add_argument('file', metavar='file', type=str)
    parser.add_argument('-a', '--decrypt', action='store_true')
    parser.add_argument('-e', '--encryption-file', type=str)
    parser.add_argument('-d', '--decryption-file', type=str)
    parser.add_argument('-c', '--chunk-size', type=int)
    return parser.parse_args()

def generate_key(key_size=2048):
    print(f"generating rsa key | size {key_size}")
    keys = RSA.generate(key_size)
    if not Path(key_path).exists():
        mkdir(key_path)
    print("saving private key...")
    with open(f"{key_path}/key_rsa", "wb") as f:
        f.write(keys.export_key())
    print("saving public key...")
    with open(f"{key_path}/key_rsa.pub", "wb") as f:
        f.write(keys.public_key().export_key())
    print('done')
    return keys

def encrypt_file(file_path: str, rsa_key: str):

    if not Path(file_path).exists():
        print(f'file path provided does not exist : {file_path}')

    print('getting rsa key info...')
    key = RSA.import_key(open(rsa_key).read())
    print('generating random aes key...')
    session_key = get_random_bytes(16)
    print('reading file...')
    with open(file_path, "rb") as f:
       data = f.read()
    
    print(f'generating and encrypting keys')
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    w_file = open(file_path, 'bw')

    # write aes data
    print("writing aes information to file...")
    print(data)
    cipher_text, tag = cipher_aes.encrypt_and_digest(data)
    [w_file.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, cipher_text)]
    
    print('closing files...')
    w_file.close()

def get_file_size(handler):
    handler.seek(0, SEEK_END)
    file_size = handler.tell()
    handler.seek(0)
    return file_size

#pylint:disable=not-callable
def decrypt_file_algo(file_path: str, rsa_key: str, chunk_size = 8192):
    print('getting rsa info...')
    key = RSA.import_key(open(rsa_key).read())
    
    print('extracting file info...')
    file_in = open(file_path, 'rb')
    file_size = get_file_size(file_in)
    enc_session_key = file_in.read(key.size_in_bytes())

    print('decrypting session key...')
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    new_file_path = file_path.removesuffix('.enc')
    file_out = open(new_file_path, 'wb')

    try:
        print('decrypting and verifying data...')
        with alive_bar(file_size, title='decrypting...') as bar:
            bar(key.size_in_bytes())
            while(data := file_in.read(chunk_size + 16 + 16)):
                nonce = data[:16]
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                tag = data[16:32]
                ciphertext = data[32:]
            
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                file_out.write(data)
                bar(len(nonce) + len(tag) + len(ciphertext))

    except KeyboardInterrupt:
        print('decryption interrupted')

    print('closing files...')
    file_in.close()
    file_out.close()

def encrypt_file_algo(file_path: str, rsa_key: str, chunk_size = 8192):
    print('getting rsa info...')
    key = RSA.import_key(open(rsa_key).read())

    print('generating random aes key...')
    session_key = get_random_bytes(16)

    print('getting file information...')
    file_in = open(file_path, 'rb')
    file_size = get_file_size(file_in)
    
    print('generating and encrypting keys...')
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    print('writing aes information to file...')
    file_out = open(f"{file_path}.enc", 'wb')
    file_out.write(enc_session_key)

    try:
        with alive_bar(file_size, title="encrypting...") as bar:
            while(data := file_in.read(chunk_size)):
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                #print(data)
                #print(f'{file_in.tell()}/{file_size}')
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                file_out.write(cipher_aes.nonce)
                file_out.write(tag)
                file_out.write(ciphertext)
                bar(len(data))
    except KeyboardInterrupt:
        print("encryption interrupted...")

    print('closing files...')
    file_in.close()
    file_out.close()

def decrypt_file(file_path: str, rsa_key: str):
    print('getting rsa key info...')
    key = RSA.import_key(open(rsa_key).read())
    print('extracting info from the file...')
    file_in = open(file_path, "rb")
    enc_session_key, nonce, tag, cipher_text = [file_in.read(x) for x in (key.size_in_bytes(), 16, 16, -1)]

    print('getting session key...')
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    print('decrypting and verifying data')
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(cipher_text, tag)
    with open(file_path, "wb") as f:
        f.write(data)
    
    print('decryption complete')
    file_in.close()


if __name__ == "__main__":
    args = setup_parser()
    
    decrypt = args.decrypt

    if decrypt:  
        if Path(args.decryption_file).exists():
            decrypt_file_algo(args.file, args.decryption_file)
        else:
            print(f"did not specify decryption file or file specified it does not exist. {args.d}")
    else:
        if Path(args.encryption_file).exists():
            encrypt_file_algo(args.file, args.encryption_file)
        else:
            print(f'did not specify encryption file or it does not exist. {args.e}')
