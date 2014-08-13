
import os
import sys
import zipfile
import io
import getpass
import argparse
import warnings
import json

# PyNaCl issues a warning every time it's imported:
#   UserWarning: reimporting '_cffi__x873aa75dx8ee09fd4' might overwrite older definitions
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
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
    minKeyEntropy = 100

def check_passphrase(pp, email):
    try:
        user, domain = email.split("@")
        domain = domain.rsplit(".", 1)[0]
    except:  # Not a valid email address, who cares jeeze
        user = email
        domain = email
    score = zxcvbn.password_strength(pp, user_inputs=[user, domain])
    if score['entropy'] >= Settings.minKeyEntropy:
        return True, score
    else:
        return False, score

def make_random_phrase(email):
    while True:
        p = phrase.generate_phrase(7)
        if check_passphrase(p, email)[0]: return p

def make_lock_securely(email = None, warn_only = False):
    "Terminal oriented; produces a prompt for user input of email and password. Returns crypto.UserLock."
    email = email or input("Please provide email address: ")
    while True:
        passphrase = getpass.getpass("Please type a secure passphrase (with spaces): ")
        ok, score = check_passphrase(passphrase, email)
        if ok: break
        print("Insufficiently strong passphrase; has {entropy} bits of entropy, could be broken in {crack_time_display}".format(**score))
        if warn_only: break
        print("Suggestion:", make_random_phrase(email))
    key = crypto.UserLock.from_passphrase(email, passphrase)
    return key
    
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
    
def decrypt_file(file_path, recipient_key, *, base64=False):
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
        crypto.assert_type_and_length('recipient_key', recipient_key, (str, crypto.UserLock))
    crypto.assert_type_and_length("sender_key", sender, crypto.UserLock)
    if (not os.path.exists(path)) or (not os.path.isdir(path)):
        raise OSError("Specified path is not a valid directory: {}".format(path))
    buf = io.BytesIO()
    zipf = zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED)
    for root, folders, files in os.walk(path):
        for fn in files:
            fp = os.path.join(root, fn)
            zipf.write(fp)
    zipf.close()
    zip_contents = buf.getvalue()
    _, filename = os.path.split(path)
    filename += ".zip"
    crypted = crypto.MiniLockFile.new(filename, zip_contents, sender, recipients)
    return crypted.contents

def error_out(message, code=1):
    print("Error:", message, file=sys.stderr)
    sys.exit(code)

def resolve_recipients(profile, recipient_list):
    recipients = []
    petnames = profile.get("petnames", [])
    for R in recipient_list:
        if crypto.UserLock.valid_id(R):
            recipients.append(R)
        else:
            if R in petnames:
                recipients.append(profile['petnames'][R])
            else:
                error_out("Recipient is not a valid ID and was not found in petnames: {}".format(R))
    return recipients    

def get_profile(A):
    "Fail-soft profile getter; if no profile is present assume none and quietly ignore."
    try:
        with open(os.path.expanduser(A.profile)) as I:
            profile = json.load(I)
        return profile
    except:
        return {}

def save_profile(A, profile):
    with open(os.path.expanduser(A.profile), "w") as O:
        O.write(json.dumps(profile, indent=2))

def main_encrypt(A):
    "Encrypt to recipient list using primary key OR prompted key. Recipients may be IDs or petnames."
    profile = get_profile(A)
    localKeys = profile.get('local keys', [])
    if not localKeys:
        localKeys = [make_lock_securely(warn_only = A.ignore_entropy)]
    else:
        localKeys = [crypto.UserLock.private_from_b64(k['private_key']) for k in localKeys]
    # First key is considered "main"
    userKey = localKeys[0]
    print("User ID:", userKey.userID)
    if not os.path.exists(A.path):
        error_out("File or directory '{}' does not exist.".format(A.path))
    # Create, fetch or error out for recipient list:
    recipients = resolve_recipients(profile, A.recipient)
    recipients.append(userKey)
    print("Recipients:", *set(k.userID if isinstance(k, crypto.UserLock) else k for k in recipients))
    # Do files OR folders
    if os.path.isfile(A.path):
        crypted = encrypt_file(A.path, userKey, recipients)
    elif os.path.isdir(A.path):
        crypted = encrypt_folder(A.path, userKey, recipients)
    else:
        error_out("Specified path '{}' is neither a file nor a folder.".format(A.path))
    if A.base64:
        crypted = crypto.b64encode(crypted)
    if not A.output:
        A.output = hex(int.from_bytes(os.urandom(6),'big'))[2:] + ".minilock"
    print("Saving output to", A.output)
    with open(A.output, "wb") as O:
        O.write(crypted)

def main_decrypt(A):
    "Get all local keys OR prompt user for key, then attempt to decrypt with each."
    profile = get_profile(A)
    localKeys = profile.get('local keys', [])
    if not localKeys:
        localKeys = [make_lock_securely(warn_only = A.ignore_entropy)]
    else:
        localKeys = [crypto.UserLock.private_from_b64(k['private_key']) for k in localKeys]
    if not os.path.exists(A.path):
        error_out("File or directory '{}' does not exist.".format(A.path))
    if os.path.isfile(A.path):
        for k in localKeys:
            print("Attempting decryption with:", k.userID)
            try:
                filename, senderID, decrypted = decrypt_file(A.path, k, base64 = A.base64)
                break
            except ValueError as E:
                pass
        else:
            error_out("Failed to decrypt with all available keys.")
    else:
        error_out("Specified path '{}' is not a file.".format(A.path))
    print("Decrypted file from", senderID)
    print("Saving output to", filename)
    with open(filename, "wb") as O:
        O.write(decrypted)

def main_generate(A):
    userLock = make_lock_securely(A.email, warn_only = A.ignore_entropy)
    print("Your new miniLock ID is:", userLock.userID)
    print("Give the above ID to anyone you want to communicate with privately to safely encrypt things to you. Remember; while your email address is used to securely generate a unique key, you can use miniLock over any medium. For output you can paste anywhere (instead of an encrypted binary file), pass the 'base64' option to deadlock in encrypt mode.")
    profile = get_profile(A)
    profile.setdefault("local keys", []).append( {
        'email': A.email, 
        'private_key': crypto.b64encode(userLock.private_key.encode()), 
        'miniLock ID':userLock.userID
        } )
    save_profile(A, profile)
    print("This will be used to attempt decryption of files in future; please be aware it is stored as plain-text on disk as {}, for security you should delete this and instead use 'deadlock decrypt' with email and passphrase each time, from memory.")
    
def main_store(A):
    profile = get_profile(A)
    petnames = profile.setdefault("petnames", {})
    petnames[A.petname] = A.miniLockID
    profile['petnames'] = petnames
    save_profile(A, profile)
    
def main():
    P = argparse.ArgumentParser(description="deadlock: A stateless Python implementation of minilock.io")
    # == Create subcommands ==
    subP = P.add_subparsers(description="Modes of operation")
    encP = subP.add_parser('encrypt')
    encP.set_defaults(func = main_encrypt)
    decP = subP.add_parser('decrypt')
    decP.set_defaults(func = main_decrypt)
    genP = subP.add_parser('generate')
    genP.set_defaults(func = main_generate)
    stoP = subP.add_parser('store')
    stoP.set_defaults(func = main_store)
    # == Begin args ==
    P.add_argument("--profile", type = str, default = "~/.deadlock.json",
            help = "Path to where profile information should be stored. Only written to when using the 'store' command, ignored if absent in all other modes. If present, used to resolve friend-names or to fetch a stored lock.")
    P.add_argument("--ignore-entropy", action = "store_true", default = False,
            help = "Permit low-entropy passphrases when generating a lock.")
    # == Encryption ==
    encP.add_argument("--base64", action = "store_true", default = False,
            help="Print a block of base64 text that can be pasted anywhere. NOT compatible with miniLock for Chrome.")
    encP.add_argument("path", type = str,
            help = "Path to file to encrypt. If a folder, it will be zipped before encryption.")
    encP.add_argument("recipient", nargs = "+", type = str,
            help = "User IDs to encrypt to")
    encP.add_argument("-o", "--output", type = str, default = '',
            help = "File to write output to, default is <8 random chars>.minilock")
    # == Decryption ==
    decP.add_argument("path", type = str,
            help = "Path to file to decrypt.")
    decP.add_argument("--base64", action="store_true", default = False,
            help = "Decrypt from a block of base64 text (saved to specified file) as created by the encryption option.")
    # == Store ==
    stoP.add_argument("miniLockID", type = str,
            help = "miniLock ID to store with a pet-name")
    stoP.add_argument("petname", type = str,
            help = "Petname or email address for the miniLock ID to be stored")
    # == Generate ==
    genP.add_argument("email", type = str,
            help = "Email address to create and store a local private Lock for")
    # == End args; Apply args ==
    A = P.parse_args()
    if hasattr(A, 'func'):
        A.func(A)
    else:
        error_out("No mode specified; use either 'encrypt' or 'decrypt', or --help for information")

