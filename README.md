# Deadlock
#### Dead-simple, Pythonic Encryption after [miniLock.io](https://minilock.io)

by Cathal Garvey, Copyright 2014, proudly licensed under the GNU Affero General Public License

* Twitter: [@onetruecathal](https://twitter.com/onetruecathal)
* Email: [cathalgarvey@cathalgarvey.me](mailto:cathalgarvey@cathalgarvey.me)
* miniLock ID: JjmYYngs7akLZUjkvFkuYdsZ3PyPHSZRBKNm6qTYKZfAM
* Gittip: [![gittip](https://img.shields.io/gittip/onetruecathal.svg)](https://www.gittip.com/onetruecathal/) 
* Bitcoin: [1QJQaR9C682HMGKHvEHWxmCvdX7SqdKzXe](bitcoin://1QJQaR9C682HMGKHvEHWxmCvdX7SqdKzXe)

![](icons/deadlock_icon.png "Sorry for killing your avi, Nadim")

## What's this?
Go to [minilock.io](https://minilock.io) to learn more about miniLock. *deadlock*
is an implementation of the miniLock protocol, and as such it is compatible with
miniLock. You can send and receive files from people using miniLock without
having to install Chrome (closed source, spyware-rich browser) or Chromium
(technically open source but by-default-still-pretty-invasive browser).

In addition to the base function of sending and receiving miniLock'd files, which
ought to be secure against snooping eyes on the wire and to provide you and your
loved/liked/other ones with a measure of deserved human privacy, *deadlock* comes
with some other features you might like:

* Auto-zipping of directories when encrypting, making it easy to send folders to friends.
* Fast underlying C implementations of core miniLock algorithms.
* Written for ease of use as a Python module, not only as a standalone application.
* No browser, easily scripted, automated or pipelined.
* "Petnames" allowing you to save IDs as easily-memorable friend names or emails
* *Highly insecure* private key storage, allowing trivial encryption/decryption,
  including iterating through all local private keys and attempting decryption with each.
* Early features for throwaway ultra-high-security addresses.
* Early features for "vanity" addresses starting or ending in a chosen word (warning: may
  take until heat-death of the universe)

## How do I install/use this?
*deadlock* is, at present, a Terminal only application, written in and for Python 3
(may only work on versions 3.3 and above; poorly tested). The best way to install
it is to use pip: 

    sudo pip install deadlock
    
..provided that you have the necessary system-level dependencies (C compiler and
supporting libraries), this ought to pull in the required cryptographic modules
from PyPI and build them, then install *deadlock*.

Once installed, *deadlock* will be available as a Python module and also as a
script, `deadlock`. Try `deadlock --help` for guidance on usage.

*deadlock* will probably work on any platform with a C compiler for the required
modules, but I have no interest in supporting closed, spyware-rich operating systems
like WinMac, so don't ask. If it doesn't work on those platforms, then you can
always fix it and send me a pull request. I don't accept pull requests for legacy
support (e.g. Python versions prior to 3.2), sorry; the code gets too messy.

## Who do I contact for support or to complain?
Nobody. This software is provided without warranty of any kind. It works, for me,
and I'm pretty sure it's secure, but I'm not going to certify it as such and you
shouldn't use it if you really need security to protect you from people with the
means and motive to harm or imprison you.

## Directions
Planned, desired or future features:
* Test suite!
* Tidier API for alternative uses of the miniLock encryption format, for P2P or
  mail client tie-in, or for RPC message passing.
* Cleaner code structure; break lots of functionality out of crypto.py/core.py into
  a new utils.py file, make core.py "dumb glue code" only.
* Fully integrate high-security keys and vanity keys, including multiprocessing
  for facilitating vanity key generation on multi-core machines. Estimated progress
  summaries for vanity key generation; time until statistically expected result, etc.
* Pure-Python fallbacks for some cryptographic dependencies for platforms that pose
  a challenge to native C compilation; Android, embedded platforms, etc.
    - Starting with tweetnacl.c/.js -> tweetnacl.py
    - Pure Python Blake2 already exists
    - Pure Python scrypt probably exists

Not currently planned:

* Contemplated adding extensions to the fileInfo dictionary within decryptInfo
  entries, but doing so would change the length of these entries which are at
  present highly predictable; this would mean that decryptInfo length could be
  used to infer which software was used to create a miniLock file, whether miniLock
  or deadlock. So, don't suggest such features, as they would partially compromise
  anonymity.
* Future versions of miniLock protocol ought to include a "mimeType"
  fileInfo key to hint to recipients whether a miniLock file is a plaintext item
  to be displayed, or a file to be saved; doing so would facilitate email integration
  of miniLock as a potential PGP successor. Again as above, such extensions would at
  present compromise anonymity somewhat.

