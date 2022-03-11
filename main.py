from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from pathlib import Path
from os import getcwd, mkdir, path, SEEK_END
from alive_progress import alive_bar
from utils import get_file_size, calculate_file_hash

from rcrypt import generate_key, encrypt_file

import argparse

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
    parser.add_argument('-f','--file', type=str)
    parser.add_argument('-a', '--decrypt', action='store_true')
    parser.add_argument('-e', '--encryption-file', type=str)
    parser.add_argument('-d', '--decryption-file', type=str)
    parser.add_argument('-c', '--chunk-size', type=int)
    parser.add_argument('-g', '--generate-rsa', type=int)

    return parser.parse_args()

#pylint:disable=not-callable
def decrypt_file_algo(file_path: str, rsa_key: str, chunk_size = 2097152):
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
    except ValueError as e:
        print(e)

    print('closing files...')
    file_in.close()
    file_out.close()

# TODO - See if running this on the GPU give any performance boost.
def encrypt_file_algo(file_path: str, rsa_key: str, chunk_size = 2097152):
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
        file_out = open(f"{file_path}.enc", 'wb')
        file_out.write(enc_session_key)

        with alive_bar(file_size, title="encrypting...") as bar:
            while(data := file_in.read(chunk_size)):
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                file_out.write(cipher_aes.nonce)
                file_out.write(tag)
                file_out.write(ciphertext)
                bar(len(data))
    except KeyboardInterrupt:
        print("encryption interrupted...")


    try:
        file_out.close()
        print('file_out handler closed...')
    except UnboundLocalError:
        print("file_out was never opened...")

    try:
        file_in.close()
        print('file_in handler closed...')
    except UnboundLocalError:
        print("file_in was never opened...")

if __name__ == "__main__":
    args = setup_parser()
    
    decrypt = args.decrypt

    if args.generate_rsa:
        generate_key(key_path, args.generate_rsa)
        exit(0)

    if decrypt:  
        if Path(args.decryption_file).exists():
            decrypt_file_algo(args.file, args.decryption_file)
        else:
            print(f"did not specify decryption file or file specified it does not exist. {args.d}")
    else:
        if Path(args.encryption_file).exists():
            encrypt_file(args.file, args.encryption_file)
        else:
            print(f'did not specify encryption file or it does not exist. {args.e}')
