import sys
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.backends import default_backend

from asn1crypto import cms, x509, pem, algos


def encrypt(certificate, data):
    # encrypt data with block cipher AES-256-CBC
    session_key = os.urandom(32)
    iv = os.urandom(16)
    algorithm = algorithms.AES(session_key)
    encryptor = Cipher(algorithm, modes.CBC(iv), backend=default_backend()).encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # load certificate
    with open(certificate, 'rb') as fp:
        cert = x509.Certificate.load(pem.unarmor(fp.read())[2])
        tbs_cert = cert['tbs_certificate']

        # encrypt session key with public key
        pub = serialization.load_der_public_key(cert.public_key.dump())
        encrypted_key = pub.encrypt(session_key, apadding.OAEP(
            mgf=apadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

    # encode encrypted key and RSA parameters for recipient
    recipient_info = cms.RecipientInfo(
        name = 'ktri',
        value = {
            'version': 'v0',
            'rid': cms.RecipientIdentifier(
                name = 'issuer_and_serial_number',
                value = {
                    'issuer': tbs_cert['issuer'],
                    'serial_number': tbs_cert['serial_number']
                }
            ),
            'key_encryption_algorithm': {
                'algorithm': 'rsaes_oaep',
                'parameters': algos.RSAESOAEPParams({
                    'hash_algorithm': {
                        'algorithm': 'sha256'
                    },
                    'mask_gen_algorithm': {
                        'algorithm': 'mgf1',
                        'parameters': {
                            'algorithm': 'sha256'
                        }
                    }
                }),
            },
            'encrypted_key': encrypted_key,
        }
    )

    # wrap up encrypted data along with symmetric encryption parameters
    # and recipient info
    enveloped_data = cms.ContentInfo({
        'content_type': 'enveloped_data',
        'content': {
            'version': 'v0',
            'recipient_infos': [recipient_info],
            'encrypted_content_info': {
                'content_type': 'data',
                'content_encryption_algorithm': {
                    'algorithm': 'aes256_cbc',
                    'parameters': iv,
                },
                'encrypted_content': encrypted_data
            }
        }
    })

    return enveloped_data

with open(sys.argv[1], 'rb') as fh:
    data = fh.read()

encrypted = encrypt(sys.argv[2], data)

with open(sys.argv[3], 'wb') as fh:
    fh.write(encrypted.dump())

print(f'Encrypted {sys.argv[1]} for {sys.argv[2]} and saved as {sys.argv[3]}.')
print(f'Decrypt with: openssl cms -decrypt -inform DER -inkey test-privatekey.pem -in {sys.argv[3]} -out dec-{sys.argv[1]}')
