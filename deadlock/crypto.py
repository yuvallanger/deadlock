"""
Implements cryptographic algorithm of miniLock, including key derivation,
symmetric encryption and asymmetric encryption of symmetric keys and authentication
data.

Much of this needs to be refactored into useful object-abstractions, and then
broken out into separate modules for simplicity and ease of re-use.
"""

import base64
import json
import os
import pyblake2
import scrypt
import nacl.public
import nacl.secret
import base58

def b64encode(*args):
    'Simple wrapper so b64encode gives string output, for clarity.'
    return base64.b64encode(*args).decode('utf8')

def b64decode(foo, *args):
    'Only here for consistency with the above.'
    if isinstance(foo, str):
        foo = foo.encode('utf8')
    return base64.b64decode(foo, *args)

def assert_type_and_length(varname, var, T, L = None, minL = None, maxL = None):
    'Facilitates simultaneous or one-line type/length checks.'
    if not isinstance(var, T):
        raise TypeError("Variable '{}' is supposed to be type '{}' but is '{}'".format(varname, T, type(var)))
    if isinstance(L, int):
        if not L == len(var):
            raise ValueError("Variable '{}' is supposed to be length {} but is {}".format(varname, L, len(var)))
    if isinstance(maxL, int):
        if maxL < len(var):
            raise ValueError("Variable '{}' is supposed to be smaller than {} but is length {}".format(varname, maxL, len(var)))
    if isinstance(minL, int):
        if minL > len(var):
            raise ValueError("Variable '{}' is supposed to be larger than {} but is length {}".format(varname, minL, len(var)))

class UserLock:
    """
    This wraps the key derivation scheme used by miniLock to construct nacl.public.PrivateKey
    and nacl.public.PublicKey objects, as well as their derived values. It can be
    constructed using either an email address and passphrase, which will yield a
    key-pair with a secret and public part, or using a miniLock ID, which will have
    only a public key part.
    
    This only wraps the task of creating or importing keys, not of their use;
    for that, use the attributes private_key or public_key.
    """
    @staticmethod
    def ensure_bytes(value):
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode('utf8')
        elif isinstance(value, bytestring):
            return bytes(value)
        else:
            raise TypeError("Value is not str, bytearray or bytes: '{}', type '{}'".format(value, type(value)))
    
    @classmethod
    def from_passphrase(cls, email, passphrase):
        """
        This performs key derivation from an email address and passphrase according
        to the miniLock specification.
        
        Specifically, the passphrase is digested with a standard blake2s 32-bit digest,
        then it is passed through scrypt with the email address as salt value using
        N = 217, r = 8, p = 1, L = 32.
        
        The 32-byte digest from scrypt is then used as the Private Key from which
        the public key is derived.
        """
        pp_blake = pyblake2.blake2s(cls.ensure_bytes(passphrase)).digest()
        pp_scrypt = scrypt.hash(pp_blake, cls.ensure_bytes(email), 2**17, 8, 1, 32)
        key = nacl.public.PrivateKey(pp_scrypt)
        return cls(key.public_key, key)

    @classmethod
    def from_id(cls, id):
        """
        This decodes an ID to a public key and verifies the checksum byte. ID
        structure in miniLock is the base58 encoded form of the public key
        appended with a single-byte digest from blake2s of the public key, as a
        simple check-sum.
        """
        decoded = cls.ensure_bytes(base58.b58decode(id))
        assert_type_and_length('id', decoded, bytes, L=33)
        pk = nacl.public.PublicKey(decoded[:-1])
        cs = decoded[-1:]
        if cs != pyblake2.blake2s(pk.encode(), 1).digest():
            raise ValueError("Public Key does not match its attached checksum byte: id='{}', decoded='{}', given checksum='{}', calculated checksum={}".format(id, decoded, cs, pyblake2.blake2s(pk.encode(), 1).digest()))
        return cls(pk)
    
    @classmethod
    def from_b64(cls, b64key):
        decoded = b64decode(b64key)
        assert_type_and_length('decoded (b64key)', decoded, bytes, L=32)
        pk = nacl.public.PublicKey(decoded)
        return cls(pk)

    @classmethod
    def private_from_b64(cls, b64key):
        decoded = b64decode(b64key)
        assert_type_and_length('decoded (b64key)', decoded, bytes)
        private_key = nacl.public.PrivateKey(decoded)
        return cls(private_key.public_key, private_key)

    @classmethod
    def ephemeral(cls):
        """
        Creates a new ephemeral key constructed using a raw 32-byte string from urandom.
        Ephemeral keys are used once for each encryption task and are then discarded;
        they are not intended for long-term or repeat use.
        """
        private_key = nacl.public.PrivateKey(os.urandom(32))
        return cls(private_key.public_key, private_key)

    @classmethod
    def fancy(cls, contains, max_tries, inner=False, keepcase=False):
        """
        Try to create a key with a chosen prefix, by starting with a 26-bit
        urandom number and appending with 8-byte integers until prefix matches.
        This function is naive, but has a max_tries argument which will abort when
        reached with a ValueError.
        TODO: make this smarter, in general. Variable byte length according to
        expected attempts, warnings of expected duration of iteration, etc. 
        TODO: Implement multiprocessing to use poly-core machines fully:
            - Shared list, each process checks if empty every cycle, aborts if
              contains a value.
            - Successful values are pushed to list, cancelling all processes?
            - Server waits on all child processes then expects a list?
            - Ensure child processes start with different random base numbers,
              to avoid duplication?
            - Investigate server/manager aspect of multiprocessing; mini-clustering?
        """
        contains = contains if keepcase else contains.lower()
        if not set(contains).issubset(base58.alphabet):
            raise ValueError("Cannot find contained phrase '{}' as it contains non-b58 characters".format(contains))
        basenum = os.urandom(26)
        for i in range(max_tries):
            k = nacl.public.PrivateKey(basenum + i.to_bytes(6, 'big'))
            ukey = cls(k.public_key, k)
            test_uid = ukey.userID if keepcase else ukey.userID.lower()
            if test_uid.startswith(contains) or test_uid.endswith(contains) or (inner and contains in test_uid):
                return ukey
        else:
            raise ValueError("Could not create key with desired prefix '{}' in {} attempts.".format(prefix, max_tries))
    
    def __init__(self, public_key, private_key=None):
        "Provide a public key and, if known, a private key. They will be verified to match."
        assert_type_and_length('public_key', public_key, nacl.public.PublicKey)
        assert_type_and_length('private_key', private_key, (nacl.public.PrivateKey, type(None)))
        self.public_key = public_key
        self.private_key = private_key
        if self.private_key and not (self.public_key.encode() == self.private_key.public_key.encode()):
            raise ValueError("Provided public key does not match the derived public key of the private key!")
    
    @property
    def b64str(self):
        return b64encode(self.public_key.encode())
    
    @property
    def userID(self):
        return base58.b58encode(   self.public_key.encode() + 
                            pyblake2.blake2s(self.public_key.encode(), 1).digest() )

    def __hash__(self):
        return int.from_bytes(self.userID.encode(), 'big')

class SymmetricMiniLock:
    """
    This wraps the symmetric encryption system used by miniLock to encrypt files.
    
    It performs the task of padding and encrypting filename, followed by chunked
    file segments with length prefixes. Encrypted chunks (starting with the name)
    are yielded by the encryption function, so this must be iterated over.
    
    When decrypting, it iterates over the length-prefixed chunks of the ciphertext,
    decrypts each (right-stripping the first of null bytes assuming it to be the
    filename), and yields each in turn; decryption, too, must be iterated over.
    """
    CHUNKSIZE = 2**20

    @classmethod
    def from_key(cls, key):
        assert_type_and_length('key', key, bytes, L=32)
        return cls(nacl.secret.SecretBox(key))

    def __init__(self, box):
        """
        'box' must be a nacl.secret.SecretBox object, constructed with the symmetric
        key. For convenience use the 'new' classmethod or the 'from_key' classmethod
        to construct from a raw binary key (which must be 32 bytes in length).
        """
        self.box  = box
        
    @staticmethod
    def pieces(array, chunk_size):
        """Yield successive chunks from array/list/string.
        Final chunk may be truncated if array is not evenly divisible by chunk_size."""
        for i in range(0, len(array), chunk_size): yield array[i:i+chunk_size]

    @staticmethod
    def make_nonce(base_nonce, chunk_number, last=False):
        assert_type_and_length('base_nonce', base_nonce, bytes, L=16)
        assert_type_and_length('chunk_number', chunk_number, int)
        n = bytearray(base_nonce + chunk_number.to_bytes(8, 'little'))
        if last:
            n[-1] |= 128
        return bytes(n)
        
    @staticmethod
    def iter_chunks(ciphertext, start_count=0):
        chunknum = start_count
        idx = 0
        lastchunk = False
        while idx < len(ciphertext):
            plainlen = int.from_bytes(ciphertext[idx: idx+4], 'little')
            chunklen = plainlen + 16
            if idx + 4 + chunklen == len(ciphertext):
                lastchunk = True
            elif idx + chunklen > len(ciphertext):
                raise ValueError("Bad ciphertext; when reading chunks, hit EOF early")
            yield chunknum, ciphertext[idx + 4 : idx + 4 + chunklen], lastchunk
            idx += chunklen + 4
            chunknum += 1

    def decrypt(self, ct, basenonce):
        assert_type_and_length('ct', ct, bytes)
        assert_type_and_length('basenonce', basenonce, bytes, L=16)
        for chunknum, chunk, lastchunk in self.iter_chunks(ct):
            this_nonce = self.make_nonce(basenonce, chunknum, lastchunk)
            decrypted = self.box.decrypt(chunk, this_nonce)
            if chunknum == 0:
                decrypted = decrypted.rstrip(b'\x00')
            yield decrypted
            
    def encrypt(self, pt, filename, basenonce):
        if isinstance(filename, str):
            filename = filename.encode('utf8')
        filename += b'\x00' * (256 - len(filename))
        assert_type_and_length('filename', filename, bytes, L=256)
        ct_chunk = self.box.encrypt(filename, self.make_nonce(basenonce, 0))[24:]
        assert_type_and_length('ct_chunk', ct_chunk, bytes, L=256+16)
        yield (256).to_bytes(4, 'little') + ct_chunk
        lastnum = (len(pt) // self.CHUNKSIZE) + 1
        for chunknum, chunk in enumerate(self.pieces(pt, self.CHUNKSIZE), start=1):
            this_nonce = self.make_nonce(basenonce, chunknum, chunknum==lastnum)
            ct_chunk = self.box.encrypt(chunk, this_nonce)[24:]
            assert_type_and_length('ct_chunk', ct_chunk, bytes, L=len(chunk)+16)
            yield len(chunk).to_bytes(4, 'little') + ct_chunk


class MiniLockHeader:
    @classmethod
    def new(cls, file_info, sender, recipients, version=1):
        """
        Constructs (encrypts) a new MiniLockHeader object.
        file_info: dict, with 'fileKey', 'fileNonce', 'fileHash' as bytes entries
        sender: UserLock for sender
        recipients: list of UserLock for recipients
        """
        ephem_key = UserLock.ephemeral()
        decryptInfo = {}
        for recipient in recipients:
            if isinstance(recipient, str):
                recipient = UserLock.from_id(recipient)
            if not isinstance(recipient, UserLock):
                raise TypeError("Recipient must be either a UserLock object or a User ID as a string.")
            # This is the sender->recipient box for the inner fileinfo.
            sending_box = nacl.public.Box(sender.private_key, recipient.public_key)
            sending_nonce = os.urandom(24)
            sending_nonce_b64 = b64encode(sending_nonce)
            # Encrypt the fileinfo sender->recipient, then create an entry for this
            # recipient with senderID/recipientID.
            dumped_fileInfo = json.dumps(file_info, separators=(',',':')).encode('utf8')
            crypted_fileInfo = sending_box.encrypt(dumped_fileInfo, sending_nonce)[24:]
            di_entry = json.dumps({
                'fileInfo'    : b64encode(crypted_fileInfo),
                'senderID'    : sender.userID,
                'recipientID' : recipient.userID
            }).encode('utf8')
            # This is the ephem->recipient box, which obfuscates the sender.
            ephem_sending_box = nacl.public.Box(ephem_key.private_key, recipient.public_key)
            crypted_di_entry = ephem_sending_box.encrypt(di_entry, sending_nonce)[24:]
            decryptInfo[sending_nonce_b64] = b64encode(crypted_di_entry)
        # Now have a decryptInfo dictionary full of entries for each recipient.
        return cls({
            'version': version,
            'ephemeral': ephem_key.b64str,  # Should be ephem_key.userID, for consistency! Support both?
            'decryptInfo': decryptInfo
        })

    @classmethod
    def from_binary(cls, header_raw):
        header_dict = json.loads(header_raw.decode('utf8'))
        return cls(header_dict)

    def __init__(self, header_dict):
        "header_dict: unaltered dict loaded from a raw header or constructed by a classmethod."
        assert_type_and_length('header_dict', header_dict, dict)
        for k in ('version', 'decryptInfo', 'ephemeral'):
            if k not in header_dict:
                raise ValueError("miniLock header missing expected key: {}".format(k))
        self.dict = header_dict

    def decrypt(self, recipient_key):
        """
        Attempt decryption of header with a private key; returns decryptInfo.
        Returns a dictionary, not a new MiniLockHeader!
        """
        ephem = UserLock.from_b64(self.dict['ephemeral'])
        ephem_box = nacl.public.Box(recipient_key.private_key, ephem.public_key)
        # Scan available entries in decryptInfo and try to decrypt each; break when
        # successful with any.
        for nonce, crypted_decryptInfo in self.dict['decryptInfo'].items():
            raw_nonce = base64.b64decode(nonce)
            crypted_decryptInfo = b64decode(crypted_decryptInfo)
            try:
                decryptInfo_raw = ephem_box.decrypt(crypted_decryptInfo, raw_nonce)
                decryptInfo = json.loads(decryptInfo_raw.decode('utf8'))
                success_nonce = raw_nonce
                break
            except Exception as E:
                #print("Decoding exception: '{}' - with ciphertext '{}'".format(E, crypted_decryptInfo))
                pass
        else:
            raise ValueError("No decryptInfo block found for this recipient Key.")
        if not recipient_key.userID == decryptInfo['recipientID']:
            raise ValueError("Decrypted a meta block but stated recipient is not this private key!")
        # Now work with decryptInfo and success_nonce to extract file data.
        senderKey = UserLock.from_id(decryptInfo['senderID'])
        senderBox = nacl.public.Box(recipient_key.private_key, senderKey.public_key)
        fileInfo_raw = base64.b64decode(decryptInfo['fileInfo'])
        fileInfo_decrypted = senderBox.decrypt(fileInfo_raw, success_nonce).decode('utf8')
        fileInfo = json.loads(fileInfo_decrypted)
        # Overwrite decryptInfo's fileInfo key
        decryptInfo['fileInfo'] = fileInfo
        return decryptInfo
        
    def to_bytes(self):
        # Remember to use separators=(',',':') in json.dumps to save space
        return json.dumps(self.dict, separators=(',',':')).encode('utf8')

class MiniLockFile:
    @classmethod
    def new(cls, file_name, file_contents, sender, recipients):
        """
        Constructs (that is, encrypts) a new miniLock file from sender to recipients.
        """
        assert_type_and_length('recipients', recipients, list, minL=1)
        assert_type_and_length('sender', sender, UserLock)
        for R in recipients:
            assert_type_and_length('recipient', R, (str, UserLock))   
        recipients = list(set(recipients))
        # Encrypt file with secret key using file_contents and file_name
        file_key   = os.urandom(32)
        file_nonce = os.urandom(16)
        file_cipher = SymmetricMiniLock.from_key(file_key)
        ciphertext = b''.join(file_cipher.encrypt(file_contents, file_name, file_nonce))
        file_info = {
            'fileKey'   : b64encode(file_key),
            'fileNonce' : b64encode(file_nonce),
            'fileHash'  : b64encode(pyblake2.blake2s(ciphertext).digest())
        }
        header = MiniLockHeader.new(file_info, sender, recipients)
        b_header = header.to_bytes()
        encrypted_file = b'miniLock' + len(b_header).to_bytes(4, 'little') + b_header + ciphertext
        return cls(encrypted_file)

    def __init__(self, contents, validate=True):
        """
        Accepts the binary content of a file, either constructed from an encryption
        classmethod or loaded from a file. Presents a verification and decryption
        interface to these contents as well as a header-extraction convenience
        property and chunk indexing system based on chunk iteration.

        By default, this will validate the information it is given to ensure it
        appears like a miniLock file; this means the 8-byte header, the header
        top-level structure, and walking the length-prefixed chunks until EOF to
        ensure they align.
        """
        self.contents = contents
        self.validate()
        
    def validate(self):
        # Confirm 8-byte leader
        if not self.contents[:8] == b'miniLock':
            raise ValueError("Magic bytes at file outset don't match miniLock")
        # Each of the below will raise exceptions on unexpected structure/input.
        header = MiniLockHeader(self.header)
        chunks = list(self.iter_chunks())

    @property
    def _header_length(self):
        return int.from_bytes(self.contents[8:12], 'little')

    @property
    def header(self):
        hdr_raw = self.contents[12: 12+self._header_length]
        return json.loads(hdr_raw.decode('utf8'))

    @property
    def chunks_block(self):
        return self.contents[12 + self._header_length:]

    def iter_chunks(self, start_count=0):
        """
        Iterate over the chunks of the file according to their length prefixes.
        yields: index <int>, encrypted chunks without length prefixes <bytes>, lastchunk <bool>
        """
        ciphertext = self.chunks_block
        chunknum = start_count
        idx = 0
        lastchunk = False
        while idx < len(ciphertext):
            plainlen = int.from_bytes(ciphertext[idx: idx+4], 'little')
            chunklen = plainlen + 16
            if idx + 4 + chunklen == len(ciphertext):
                lastchunk = True
            elif idx + chunklen > len(ciphertext):
                raise ValueError("Bad ciphertext; when reading chunks, hit EOF early")
            yield chunknum, ciphertext[idx + 4 : idx + 4 + chunklen], lastchunk
            idx += chunklen + 4
            chunknum += 1

    def decrypt(self, recipient_key):
        """
        recipient_key: UserLock with a private key part.
        returns: filename, decrypted file contents
        """
        if recipient_key.private_key is None:
            raise ValueError("Cannot decrypt with this key; no private key part found.")
        header = MiniLockHeader(self.header)
        # Create ephemeral public key for authenticated decryption of metadata.
        # TODO: Future-proof this by making it try to decrypt a b58 ephem ID if available?
        decryptInfo = header.decrypt(recipient_key)
        file_info = decryptInfo['fileInfo']
        file_hash = file_info['fileHash']
        if not b64decode(file_hash) == pyblake2.blake2s(self.chunks_block).digest():
            raise ValueError("ciphertext does not match given hash!")
        symbox = SymmetricMiniLock.from_key(base64.b64decode(file_info['fileKey']))
        filename, *filechunks = symbox.decrypt(self.chunks_block, b64decode(file_info['fileNonce']))
        try:
            filename = filename.decode('utf8')
        except Exception as E:
            raise ValueError("Cannot decode filename to UTF8 string: '{}'".format(filename))
        sender = decryptInfo['senderID']
        return filename, sender, b''.join(filechunks)

