# cms-encryption
This code demonstrates how to reproduce CMS encryption with openssl with Python libraries.

```sh
python3 -m venv .ve
.ve/bin/pip install -r requirements.txt

echo "Hello World" > file.txt
openssl cms -encrypt -in file.txt -out file.enc -recip test-certificate.pem -keyopt rsa_padding_mode:oaep -aes-256-cbc -outform DER -binary
.ve/bin/python encrypt.py file.txt test-certificate.pem file2.enc

openssl cms -decrypt -inform DER -inkey test-privatekey.pem -out file-dec.txt -in file.enc
openssl cms -decrypt -inform DER -inkey test-privatekey.pem -out file2-dec.txt -in file2.enc

cat file*-dec.txt
```
