import json,random,hashlib,os.path,base64
from flask import Flask,request
from Crypto.Cipher import AES

app = Flask(__name__)

def encrypt(text):
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    padding_length = 16 - (len(text) % 16)
    chunk = text + padding_length * chr(padding_length)
    ciphertext = encryptor.encrypt(chunk)
    return ciphertext, iv

def decrypt(ciphertext,iv):
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    return decryptor.decrypt(ciphertext)
    
@app.route('/encrypt', methods = ['POST'])
def encrypt_request():
    #if request.method == 'POST':
    ciphertext,iv=encrypt(request.json["secret"])
    element={
        "secret": base64.b64encode(ciphertext),
        "iv": base64.b64encode(iv),
        "author": "N/A", 
        "description": "TEST", 
        "expiration": "OTA" 
    }
    secrets.append(element)
    return base64.b64encode(iv)

@app.route('/decrypt', methods = ['POST'])
def decrypt_request():
    for element in secrets[1:]:
        print element
        if element["iv"] == request.json["iv"]:
            plaintext=decrypt(base64.b64decode(element["secret"]),base64.b64decode(element["iv"]))
            return plaintext
    return "NOT FOUND"

if __name__ == '__main__':
    file='secrets.json'
    passphrase = 'test__key'
    #hardened key through hashing + padding dismissed due to hash output 32-bytes
    key = hashlib.sha256(passphrase).digest()
    secrets=[{}]
    app.run()