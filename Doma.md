**Practical 1: Password Salting \& Hashing**



**AIM: Program to implement password salting and hashing to create secure passwords.** 



import hashlib, os



def hash\_password(password):

&nbsp;   salt = os.urandom(16)

&nbsp;   password\_bytes = password.encode('utf-8')

&nbsp;   salted\_password = salt + password\_bytes

&nbsp;   hashed = hashlib.sha256(salted\_password).hexdigest()

&nbsp;   return salt.hex(), hashed



def verify\_password(stored\_salt, stored\_hash, password\_to\_check):

&nbsp;   salt = bytes.fromhex(stored\_salt)

&nbsp;   password\_bytes = password\_to\_check.encode('utf-8')

&nbsp;   hashed = hashlib.sha256(salt + password\_bytes).hexdigest()

&nbsp;   return hashed == stored\_hash





original\_password = input("Create a password: ")

salt, hashed\_password = hash\_password(original\_password)

print("\\nStored Salt:", salt)

print("Stored Hash:", hashed\_password)



login\_password = input("\\nEnter password to login: ")

if verify\_password(salt, hashed\_password, login\_password):

&nbsp;   print(" Password correct!")

else:

&nbsp;   print(" Wrong password!")



&nbsp;



&nbsp;



**🔠 Practical 2 – Classical Ciphers (Substitution, Vigenère, Affine)**

**AIM : Program to implement various classical ciphers – Substitution** 

**Cipher, Vigenère Cipher, and Affine Cipher.**

def substitution\_encrypt(text, shift):

&nbsp;   result = ""

&nbsp;   for char in text:

&nbsp;       if char.isalpha():

&nbsp;           base = ord('A') if char.isupper() else ord('a')

&nbsp;           result += chr((ord(char)-base+shift)%26+base)

&nbsp;       else:

&nbsp;           result += char

&nbsp;   return result



def substitution\_decrypt(text, shift):

&nbsp;   return substitution\_encrypt(text, -shift)



def vigenere\_encrypt(text, key):

&nbsp;   result, key = "", key.lower()

&nbsp;   for i, ch in enumerate(text):

&nbsp;       if ch.isalpha():

&nbsp;           shift = ord(key\[i % len(key)]) - ord('a')

&nbsp;           base = ord('A') if ch.isupper() else ord('a')

&nbsp;           result += chr((ord(ch)-base+shift)%26+base)

&nbsp;       else:

&nbsp;           result += ch

&nbsp;   return result



def vigenere\_decrypt(text, key):

&nbsp;   result, key = "", key.lower()

&nbsp;   for i, ch in enumerate(text):

&nbsp;       if ch.isalpha():

&nbsp;           shift = ord(key\[i % len(key)]) - ord('a')

&nbsp;           base = ord('A') if ch.isupper() else ord('a')

&nbsp;           result += chr((ord(ch)-base-shift)%26+base)

&nbsp;       else:

&nbsp;           result += ch

&nbsp;   return result



def mod\_inverse(a, m):

&nbsp;   for i in range(1, m):

&nbsp;       if (a \* i) % m == 1:

&nbsp;           return i

&nbsp;   return None



def affine\_encrypt(text, a, b):

&nbsp;   result = ""

&nbsp;   for ch in text:

&nbsp;       if ch.isalpha():

&nbsp;           base = ord('A') if ch.isupper() else ord('a')

&nbsp;           x = ord(ch) - base

&nbsp;           result += chr(((a\*x + b) % 26) + base)

&nbsp;       else:

&nbsp;           result += ch

&nbsp;   return result



def affine\_decrypt(text, a, b):

&nbsp;   a\_inv = mod\_inverse(a, 26)

&nbsp;   result = ""

&nbsp;   for ch in text:

&nbsp;       if ch.isalpha():

&nbsp;           base = ord('A') if ch.isupper() else ord('a')

&nbsp;           y = ord(ch) - base

&nbsp;           result += chr((a\_inv \* (y - b)) % 26 + base)

&nbsp;       else:

&nbsp;           result += ch

&nbsp;   return result



print("1. Substitution\\n2. Vigenere\\n3. Affine")

choice = input("Enter choice: ")

msg = input("Message: ")



if choice == '1':

&nbsp;   s = int(input("Shift: "))

&nbsp;   enc = substitution\_encrypt(msg, s)

&nbsp;   print("Encrypted:", enc)

&nbsp;   print("Decrypted:", substitution\_decrypt(enc, s))

elif choice == '2':

&nbsp;   k = input("Key: ")

&nbsp;   enc = vigenere\_encrypt(msg, k)

&nbsp;   print("Encrypted:", enc)

&nbsp;   print("Decrypted:", vigenere\_decrypt(enc, k))

else:

&nbsp;   a, b = 5, 8

&nbsp;   enc = affine\_encrypt(msg, a, b)

&nbsp;   print("Encrypted:", enc)

&nbsp;   print("Decrypted:", affine\_decrypt(enc, a, b))



&nbsp;



**🧮 Practical 3 – Cryptanalysis (Breaking Caesar \& Vigenère)**

**AIM :Program to demonstrate cryptanalysis (e.g., breaking Caesar** 

**or Vigener Cipher)**  

&nbsp;



def caesar\_decrypt(text, shift):

&nbsp;   result = ""

&nbsp;   for ch in text:

&nbsp;       if ch.isalpha():

&nbsp;           base = ord('A') if ch.isupper() else ord('a')

&nbsp;           result += chr((ord(ch)-base-shift)%26+base)

&nbsp;       else:

&nbsp;           result += ch

&nbsp;   return result



cipher = "Khoor Zruog"

print("=== Caesar Cipher Brute Force ===")

for i in range(26):

&nbsp;   print(f"Key {i}: {caesar\_decrypt(cipher, i)}")



def vigenere\_decrypt(text, key):

&nbsp;   key = key.lower()

&nbsp;   result, i = "", 0

&nbsp;   for ch in text:

&nbsp;       if ch.isalpha():

&nbsp;           shift = ord(key\[i % len(key)]) - ord('a')

&nbsp;           base = ord('A') if ch.isupper() else ord('a')

&nbsp;           result += chr((ord(ch)-base-shift)%26+base)

&nbsp;           i += 1

&nbsp;       else:

&nbsp;           result += ch

&nbsp;   return result



print("\\n=== Vigenere Known Key ===")

print(vigenere\_decrypt("Rijvs Uyvjn", "key"))



&nbsp;



**🧱 Practical 4 – AES File Encryption \& Decryption**

**Aim : Program to implement AES algorithm for file encryption and** 

**decryption** 

**command run in terminal--> pip install cryptography**



import os

import argparse

import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.exceptions import InvalidTag



\# Constants

SALT\_SIZE = 16

NONCE\_SIZE = 12

KEY\_SIZE = 32

PBKDF2\_ITERATIONS = 600\_000



def derive\_key(password: str, salt: bytes) -> bytes:

&nbsp;   """Derive a symmetric key from password using PBKDF2-HMAC-SHA256."""

&nbsp;   kdf = PBKDF2HMAC(

&nbsp;       algorithm=hashes.SHA256(),

&nbsp;       length=KEY\_SIZE,

&nbsp;       salt=salt,

&nbsp;       iterations=PBKDF2\_ITERATIONS,

&nbsp;   )

&nbsp;   return kdf.derive(password.encode('utf-8'))



def encrypt\_file(input\_file: str, output\_file: str, password: str):

&nbsp;   """Encrypt file using AES-GCM."""

&nbsp;   with open(input\_file, 'rb') as f:

&nbsp;       plaintext = f.read()



&nbsp;   salt = os.urandom(SALT\_SIZE)

&nbsp;   nonce = os.urandom(NONCE\_SIZE)

&nbsp;   key = derive\_key(password, salt)

&nbsp;   aesgcm = AESGCM(key)



&nbsp;   ciphertext = aesgcm.encrypt(nonce, plaintext, None)



&nbsp;   with open(output\_file, 'wb') as f:

&nbsp;       f.write(salt + nonce + ciphertext)



&nbsp;   print(f"✅ File encrypted successfully: {output\_file}")



def decrypt\_file(input\_file: str, output\_file: str, password: str):

&nbsp;   """Decrypt AES-GCM file."""

&nbsp;   with open(input\_file, 'rb') as f:

&nbsp;       data = f.read()



&nbsp;   salt = data\[:SALT\_SIZE]

&nbsp;   nonce = data\[SALT\_SIZE:SALT\_SIZE+NONCE\_SIZE]

&nbsp;   ciphertext = data\[SALT\_SIZE+NONCE\_SIZE:]



&nbsp;   key = derive\_key(password, salt)

&nbsp;   aesgcm = AESGCM(key)



&nbsp;   try:

&nbsp;       plaintext = aesgcm.decrypt(nonce, ciphertext, None)

&nbsp;   except InvalidTag:

&nbsp;       print("❌ Decryption failed! Wrong password or corrupted file.")

&nbsp;       return



&nbsp;   with open(output\_file, 'wb') as f:

&nbsp;       f.write(plaintext)



&nbsp;   print(f"✅ File decrypted successfully: {output\_file}")



def main():

&nbsp;   parser = argparse.ArgumentParser(description="AES-GCM file encrypt/decrypt")

&nbsp;   parser.add\_argument("mode", choices=\["encrypt", "decrypt"], help="Mode: encrypt or decrypt")

&nbsp;   parser.add\_argument("input", help="Input file path")

&nbsp;   parser.add\_argument("output", help="Output file path")

&nbsp;   args = parser.parse\_args()



&nbsp;   password = getpass.getpass("Enter password: ")



&nbsp;   if args.mode == "encrypt":

&nbsp;       confirm = getpass.getpass("Confirm password: ")

&nbsp;       if password != confirm:

&nbsp;           print("❌ Passwords do not match.")

&nbsp;           return

&nbsp;       encrypt\_file(args.input, args.output, password)

&nbsp;   else:

&nbsp;       decrypt\_file(args.input, args.output, password)



if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   main()



&nbsp;



**🧩 Practical 5 — Implement Various Block Cipher Modes (ECB, CBC, CFB, OFB, CTR)**



**COMMAND TO RUN IN TERMINAL --> pip install pycryptodome**





from Crypto.Cipher import AES

from Crypto.Random import get\_random\_bytes

from Crypto.Util.Padding import pad, unpad

from Crypto.Util import Counter



key = get\_random\_bytes(16)

plaintext = b"Hello Students! Let's learn Block Cipher Modes."



print(" Original Plaintext:", plaintext)



cipher\_ecb = AES.new(key, AES.MODE\_ECB)

ciphertext\_ecb = cipher\_ecb.encrypt(pad(plaintext, AES.block\_size))

print("\\n\[ECB] Ciphertext:", ciphertext\_ecb)



decipher\_ecb = AES.new(key, AES.MODE\_ECB)

decrypted\_ecb = unpad(decipher\_ecb.decrypt(ciphertext\_ecb), AES.block\_size)

print("\[ECB] Decrypted:", decrypted\_ecb)



iv\_cbc = get\_random\_bytes(16)

cipher\_cbc = AES.new(key, AES.MODE\_CBC, iv\_cbc)

ciphertext\_cbc = cipher\_cbc.encrypt(pad(plaintext, AES.block\_size))

print("\\n\[CBC] Ciphertext:", ciphertext\_cbc)



decipher\_cbc = AES.new(key, AES.MODE\_CBC, iv\_cbc)

decrypted\_cbc = unpad(decipher\_cbc.decrypt(ciphertext\_cbc), AES.block\_size)

print("\[CBC] Decrypted:", decrypted\_cbc)



iv\_cfb = get\_random\_bytes(16)

cipher\_cfb = AES.new(key, AES.MODE\_CFB, iv\_cfb)

ciphertext\_cfb = cipher\_cfb.encrypt(plaintext)

print("\\n\[CFB] Ciphertext:", ciphertext\_cfb)



decipher\_cfb = AES.new(key, AES.MODE\_CFB, iv\_cfb)

decrypted\_cfb = decipher\_cfb.decrypt(ciphertext\_cfb)

print("\[CFB] Decrypted:", decrypted\_cfb)



iv\_ofb = get\_random\_bytes(16)

cipher\_ofb = AES.new(key, AES.MODE\_OFB, iv\_ofb)

ciphertext\_ofb = cipher\_ofb.encrypt(plaintext)

print("\\n\[OFB] Ciphertext:", ciphertext\_ofb)



decipher\_ofb = AES.new(key, AES.MODE\_OFB, iv\_ofb)

decrypted\_ofb = decipher\_ofb.decrypt(ciphertext\_ofb)

print("\[OFB] Decrypted:", decrypted\_ofb)



ctr = Counter.new(128)

cipher\_ctr = AES.new(key, AES.MODE\_CTR, counter=ctr)

ciphertext\_ctr = cipher\_ctr.encrypt(plaintext)

print("\\n\[CTR] Ciphertext:", ciphertext\_ctr)



ctr = Counter.new(128)

decipher\_ctr = AES.new(key, AES.MODE\_CTR, counter=ctr)

decrypted\_ctr = decipher\_ctr.decrypt(ciphertext\_ctr)

print("\[CTR] Decrypted:", decrypted\_ctr)





**Practical 6 — Steganography (Hide Messages Inside Images)**

 

**command to enter in terminal --> pip install pillow**



from PIL import Image



def hide\_message(image\_path, message, output\_path):

&nbsp;   img = Image.open("image path here //")

&nbsp;   encoded = img.copy()

&nbsp;   width, height = img.size

&nbsp;   index = 0



&nbsp;   message += "###"



&nbsp;   for row in range(height):

&nbsp;       for col in range(width):

&nbsp;           if index < len(message) \* 8:

&nbsp;               pixel = list(img.getpixel((col, row)))

&nbsp;               ascii\_val = ord(message\[index // 8])

&nbsp;               bit\_val = (ascii\_val >> (index % 8)) \& 1

&nbsp;               pixel\[0] = pixel\[0] \& ~1 | bit\_val

&nbsp;               encoded.putpixel((col, row), tuple(pixel))

&nbsp;               index += 1



&nbsp;   encoded.save(output\_path)

&nbsp;   print(f"✅ Message hidden successfully in '{output\_path}'")





def reveal\_message(image\_path):

&nbsp;   img = Image.open(image\_path)

&nbsp;   width, height = img.size

&nbsp;   bits = \[]

&nbsp;   message = ""



&nbsp;   for row in range(height):

&nbsp;       for col in range(width):

&nbsp;           pixel = list(img.getpixel((col, row)))

&nbsp;           bits.append(pixel\[0] \& 1)



&nbsp;           if len(bits) == 8:

&nbsp;               char = chr(int("".join(str(bit) for bit in bits\[::-1]), 2))

&nbsp;               message += char

&nbsp;               bits = \[]

&nbsp;               if message.endswith("###"):

&nbsp;                   print(" Hidden message found successfully!")

&nbsp;                   return message\[:-3]

&nbsp;   return message





if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   hide\_message("input.png", "Hello Students! Secret message inside.", "encoded.png")

&nbsp;   secret = reveal\_message("encoded.png")

&nbsp;   print("🔍 Hidden message:", secret)

&nbsp;



**🔹 Practical 7: HMAC for Signing Messages**



import hmac

import hashlib



def generate\_hmac(key, message):

&nbsp;   signature = hmac.new(key.encode(), message.encode(), hashlib.sha256)

&nbsp;   return signature.hexdigest()



def verify\_hmac(key, message, signature):

&nbsp;   new\_signature = generate\_hmac(key, message)

&nbsp;   return hmac.compare\_digest(new\_signature, signature)



if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   secret\_key = "my\_secret\_key"

&nbsp;   message = "Hello Students!"

&nbsp;   signature = generate\_hmac(secret\_key, message)

&nbsp;   print("Message:", message)

&nbsp;   print("HMAC Signature:", signature)

&nbsp;   is\_valid = verify\_hmac(secret\_key, message, signature)

&nbsp;   print("Is the signature valid?", is\_valid)

🔹 Practical 8: Secure Messaging Over IP (AES-GCM)

receiver.py



code :



import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM



HOST = '127.0.0.1'

PORT = 65432

KEY = b"0123456789abcdef0123456789abcdef"



def start\_server():

&nbsp;   print("Server running...")

&nbsp;   with socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) as s:

&nbsp;       s.bind((HOST, PORT))

&nbsp;       s.listen()

&nbsp;       conn, addr = s.accept()

&nbsp;       with conn:

&nbsp;           print(f"Connected by {addr}")

&nbsp;           nonce = conn.recv(12)

&nbsp;           ciphertext = conn.recv(1024)

&nbsp;           aesgcm = AESGCM(KEY)

&nbsp;           try:

&nbsp;               plaintext = aesgcm.decrypt(nonce, ciphertext, None)

&nbsp;               print("Decrypted message:", plaintext.decode())

&nbsp;           except Exception as e:

&nbsp;               print("Decryption failed:", e)



if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   start\_server()

&nbsp;



&nbsp;



**2nd file open in different terminal sender.py**

import socket, os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM



HOST = '127.0.0.1'

PORT = 65432

KEY = b"0123456789abcdef0123456789abcdef"



def send\_secure\_message(message):

&nbsp;   aesgcm = AESGCM(KEY)

&nbsp;   nonce = os.urandom(12)

&nbsp;   ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

&nbsp;   with socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) as s:

&nbsp;       s.connect((HOST, PORT))

&nbsp;       s.sendall(nonce)

&nbsp;       s.sendall(ciphertext)

&nbsp;   print("Original:", message)

&nbsp;   print("Ciphertext:", ciphertext)



if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   send\_secure\_message("Top secret message over the network!")

&nbsp;



**🔹 Practical 9: RSA Encryption/Decryption**





from Crypto.PublicKey import RSA

from Crypto.Cipher import PKCS1\_OAEP



key = RSA.generate(2048)



private\_key = key.export\_key()

public\_key = key.publickey().export\_key()



print("🔑 Private Key:")

print(private\_key.decode())



print("\\n🔑 Public Key:")

print(public\_key.decode())



private\_key\_obj = RSA.import\_key(private\_key)

public\_key\_obj = RSA.import\_key(public\_key)



encryptor = PKCS1\_OAEP.new(public\_key\_obj)

decryptor = PKCS1\_OAEP.new(private\_key\_obj)



message = "Hello Students, RSA is secure!"

print("\\n📩 Original Message:", message)



encrypted\_msg = encryptor.encrypt(message.encode())

print("\\n🔒 Encrypted Message:", encrypted\_msg)



decrypted\_msg = decryptor.decrypt(encrypted\_msg).decode()

print("\\n🔓 Decrypted Message:", decrypted\_msg)

&nbsp;



**🔹 Practical 10: AIM: Program to implement (i) El-Gamal Cryptosystem (ii) Elliptic Curve Cryptography** 

&nbsp;

**File name:**

**elgamal.py**



from Crypto.Random import random

from Crypto.Util.number import getPrime, inverse



def generate\_keys(bits=256):

&nbsp;   p = getPrime(bits)

&nbsp;   g = random.randint(2, p - 1)

&nbsp;   x = random.randint(1, p - 2)

&nbsp;   y = pow(g, x, p)

&nbsp;   return (p, g, y), x



def encrypt(p, g, y, message):

&nbsp;   k = random.randint(1, p - 2)

&nbsp;   c1 = pow(g, k, p)

&nbsp;   s = pow(y, k, p)

&nbsp;   c2 = (s \* message) % p

&nbsp;   return c1, c2



def decrypt(p, x, c1, c2):

&nbsp;   s = pow(c1, x, p)

&nbsp;   s\_inv = inverse(s, p)

&nbsp;   return (c2 \* s\_inv) % p



if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   public\_key, private\_key = generate\_keys()

&nbsp;   p, g, y = public\_key

&nbsp;   message = 12345

&nbsp;   c1, c2 = encrypt(p, g, y, message)

&nbsp;   print("Encrypted:", (c1, c2))

&nbsp;   print("Decrypted:", decrypt(p, private\_key, c1, c2))

filename  2d file Ecc.py:

&nbsp;



from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os



def generate\_ecc\_keys():

&nbsp;   private\_key = ec.generate\_private\_key(ec.SECP256R1())

&nbsp;   return private\_key, private\_key.public\_key()



def encrypt\_message(sender\_private, receiver\_public, plaintext):

&nbsp;   shared = sender\_private.exchange(ec.ECDH(), receiver\_public)

&nbsp;   derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecc').derive(shared)

&nbsp;   aesgcm = AESGCM(derived)

&nbsp;   nonce = os.urandom(12)

&nbsp;   ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

&nbsp;   return nonce, ciphertext



def decrypt\_message(receiver\_private, sender\_public, nonce, ciphertext):

&nbsp;   shared = receiver\_private.exchange(ec.ECDH(), sender\_public)

&nbsp;   derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecc').derive(shared)

&nbsp;   aesgcm = AESGCM(derived)

&nbsp;   return aesgcm.decrypt(nonce, ciphertext, None).decode()



if \_\_name\_\_ == "\_\_main\_\_":

&nbsp;   sender\_priv, sender\_pub = generate\_ecc\_keys()

&nbsp;   receiver\_priv, receiver\_pub = generate\_ecc\_keys()

&nbsp;   msg = "Python is a Programming Language"

&nbsp;   nonce, ciphertext = encrypt\_message(sender\_priv, receiver\_pub, msg)

&nbsp;   print("Encrypted:", ciphertext.hex())

&nbsp;   print("Decrypted:", decrypt\_message(receiver\_priv, sender\_pub, nonce, ciphertext))

