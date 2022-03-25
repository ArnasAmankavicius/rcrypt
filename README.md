# rcrypt
RSA file encryption

## How it works?
It's rather simple. It uses pycrytodome library to use generate a 16-byte key which gets used as an AES session-key. This session key is then used to encrypt the file contents. The key itself is encrypted using an RSA public key and stored in the file itself. The session key can only be retreived by an appropriate RSA private key.

## Usage
To encrypt a file use the following:

`python main.py -f file_path -e rsa_pubkey`

To decrypt a file use the following:

`python main.py -f file_path -a -d rsa_privkey`

To generate the RSA pair:

`python main.py -g key_size`

## Developers

- Me - Primary code dev and review.