
import os
import sys
import zipfile
import tempfile
import getpass
import argparse

from . import crypto
from .passwords import zxcvbn, phrase

__all__ = [ 'Settings',
            'check_passphrase',
            'make_random_phrase',
            'make_key_securely',
            'encrypt_file',
            'decrypt_file',
            'encrypt_folder' ]

class Settings:
    minPassphraseEntropy = 100
    minKeyEntropy = 100

def check_passphrase(pp, email):
    user, domain = email.split("@")
    domain = domain.rsplit(".", 1)[0]
    score = zxcvbn.password_strength(pp, user_inputs=[user, domain])
    if score['entropy'] >= Settings.minKeyEntropy:
        return True, score
    else:
        return False, score

def make_random_phrase(email):
    while True:
        p = phrase.generate_phrase(7)
        if check_passphrase(p, email)[0]: return p

def make_lock_securely():
    "Terminal oriented; produces a prompt for user input of email and password. Returns crypto.UserLock."
    email = input("Please provide email address: ")
    while True:
        passphrase = getpass.getpass("Please type a secure passphrase (with spaces): ")
        ok, score = check_passphrase(passphrase, email)
        if ok: break
        print("Insufficiently strong passphrase; has {entropy} bits of entropy, could be broken in {crack_time_display}".format(**score))
        print("Suggestion:", make_random_phrase(email))
    key = crypto.UserKey.from_passphrase(email, passphrase)
    
def encrypt_file(file_path, sender, recipients):
    "Returns encrypted binary file content if successful"
    for recipient_key in recipients:
        crypto.assert_type_and_length('recipient_key', recipient_key, (str, crypto.UserLock))
    crypto.assert_type_and_length("sender_key", sender, crypto.UserLock)
    if (not os.path.exists(file_path)) or (not os.path.isfile(file_path)):
        raise OSError("Specified path does not point to a valid file: {}".format(file_path))
    _, filename = os.path.split(file_path)
    with open(file_path, "rb") as I:
        crypted = crypto.MiniLockFile.new(filename, I.read(), sender, recipients)
    return crypted.contents
    
def decrypt_file(file_path, recipient_key, base64=False):
    "Returns (filename, file_contents) if successful"
    crypto.assert_type_and_length('recipient_key', recipient_key, crypto.UserLock)
    with open(file_path, "rb") as I:
        contents = I.read()
        if base64:
            contents = crypto.b64decode(contents)
        crypted = crypto.MiniLockFile(contents)
    return crypted.decrypt(recipient_key)

def encrypt_folder(path, sender, recipients):
    """
    This helper function should zip the contents of a folder and encrypt it as
    a zip-file. Recipients are responsible for opening the zip-file.
    """
    for recipient_key in recipients:
        crypto.assert_type_and_length('recipient_key', recipient_key, (str, UserLock))
    crypto.assert_type_and_length("sender_key", sender, UserLock)
    if (not os.path.exists(path)) or (not os.path.isdir(path)):
        raise OSError("Specified path is not a valid directory: {}".format(path))
    tempf = tempfile.TemporaryFile()
    zipf = zipfile(tempf, mode="w", compression=zipfile.ZIP_DEFLATED)
    for root, folders, files in os.walk(path):
        for fn in files:
            fp = os.path.join(root, fp)
            zipf.write(fp)
    tempf.flush()
    tempf.seek(0)
    zip_contents = tempf.read()
    _, filename = os.path.split(path)
    filename += ".zip"
    crypted = crypto.MiniLockFile.new(filename, zip_contents, sender, recipients)
    return crypted.contents

def error_out(message, code=1):
    print("Error:", message, file=sys.stderr)
    sys.exit(code)

def main_encrypt(A):
    A.userKey = make_lock_securely()
    if not os.path.exists(A.path):
        error_out("File or directory '{}' does not exist.".format(A.path))
    if os.path.isfile(A.path):
        crypted = encrypt_file(A.path, A.userKey, [A.userKey, A.recipients])
    elif os.path.isdir(A.path):
        crypted = encrypt_folder(A.path, A.userKey, [A.userKey, A.recipients])
    else:
        error_out("Specified path '{}' is neither a file nor a folder.".format(A.path))
    if A.base64:
        crypted = crypto.b64encode(crypted)
    A.output.write(crypted)

def main_decrypt(A):
    A.userKey = make_lock_securely()
    if not os.path.exists(A.path):
        error_out("File or directory '{}' does not exist.".format(A.path))
    if os.path.isfile(A.path):
        filename, decrypted = decrypt_file(A.path, A.userKey, base64 = A.base64)
    else:
        error_out("Specified path '{}' is not a file.".format(A.path))
    with open(filename, "wb") as O:
        O.write(decrypted)

def main_generate(A):
    A.userKey = make_lock_securely()
    print("Your miniLock ID is:", A.userLock.userID)
    print("Give this to anyone you want to communicate with privately to safely encrypt things to you. Remember; while your email address is used to securely generate a unique key, you can use miniLock over any medium. For output you can paste anywhere (instead of an encrypted binary file), pass the 'base64' option to deadlock in encrypt mode.")
    
def main():
    P = argparse.ArgumentParser(description="deadlock: A stateless Python implementation of minilock.io")
    P.set_defaults(func = lambda A: error_out("No mode specified; use either 'encrypt' or 'decrypt', or --help for information"))
    # == Create subcommands ==
    subP = P.add_subparsers(description="Modes of operation")
    encP = subP.add_parser()
    encP.set_defaults(func = main_encrypt)
    decP = subP.add_parser()
    decP.set_defaults(func = main_decrypt)
    genP = subP.add_parser()
    genP.set_defaults(func = main_generate)
    # == Begin args ==
    # == Encryption ==
    encP.add_argument("--base64", action="store_true", default=False,
            help="Print a block of base64 text that can be pasted anywhere. NOT compatible with miniLock for Chrome.")
    encP.add_argument("path", type=str,
            help = "Path to file to encrypt. If a folder, it will be zipped before encryption.")
    encP.add_argument("-o", "--output", type=argparse.FileType("wb"), default=sys.stdout.buffer,
            help = "File or stream to write output to, default is stdout.")
    # == Decryption ==
    decP.add_argument("path", type=str,
            help = "Path to file to decrypt.")
    decP.add_argument("--base64", action="store_true", default=False,
            help="Decrypt from a block of base64 text (saved to specified file) as created by the encryption option.")
    # == Generate ==
    # == End args; Apply args ==
    A = P.parse_args()
    A.func(A)
