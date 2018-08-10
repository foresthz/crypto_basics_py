'''
Created on 2018-08-10

@author: steven
'''

# using pycrypto

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto import Random

rsa = RSA.generate(1024, Random.new().read)
private_key = rsa.exportKey()
public_key = rsa.publickey().exportKey()

print('private_key: ', private_key)
print('public_key: ', public_key)

from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS
import base64
public = RSA.importKey(public_key)
cipher = Cipher_PKCS.new(public)
raw_text = b'hello world'
# cipher.encrypt(raw_text)
base64_cipher_text = base64.b64encode(cipher.encrypt(raw_text))
print('base64 cipher text: ', base64_cipher_text)

private = RSA.importKey(private_key)
decipher = Cipher_PKCS.new(private)
decipher_text = decipher.decrypt(base64.b64decode(base64_cipher_text), Random.new().read)
print('decepher text: ', decipher_text)