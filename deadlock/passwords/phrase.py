# Based on miniLock.phrase, phrase.py is a library that returns n-word passphrases
# randomly selected from the 58,110 most used words in the English language.
# With this many words, a 7-word passphrase is equivalent to ~111 bits of entropy.

import os
import random
from . import wordlist

def secure_choice(sequence):
    "Returns a single item from sequence using random.choice after seeding with 32 bytes of urandom."
    random.seed(os.urandom(32))
    return random.choice(sequence)
    
def generate_phrase(phrase_length=7):
    return ' '.join((secure_choice(wordlist.wordlist) for i in range(phrase_length)))
