Deadlock
========

Dead-simple, Pythonic Encryption after `miniLock.io <https://minilock.io>`__
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

by Cathal Garvey, Copyright 2014, proudly licensed under the GNU Affero
General Public License

-  Twitter: [@onetruecathal](https://twitter.com/onetruecathal)
-  Email: cathalgarvey@cathalgarvey.me
-  miniLock ID: JjmYYngs7akLZUjkvFkuYdsZ3PyPHSZRBKNm6qTYKZfAM
-  Gittip: https://www.gittip.com/onetruecathal
-  Bitcoin:
   `1QJQaR9C682HMGKHvEHWxmCvdX7SqdKzXe <bitcoin://1QJQaR9C682HMGKHvEHWxmCvdX7SqdKzXe>`__

What's this?
------------

Go to `minilock.io <https://minilock.io>`__ to learn more about
miniLock. *deadlock* is an implementation of the miniLock protocol, and
as such it is compatible with miniLock. You can send and receive files
from people using miniLock without having to install Chrome (closed
source, spyware-rich browser) or Chromium (technically open source but
by-default-still-pretty-invasive browser).

In addition to the base function of sending and receiving miniLock'd
files, which ought to be secure against snooping eyes on the wire and to
provide you and your loved/liked/other ones with a measure of deserved
human privacy, *deadlock* comes with some other features you might like:

-  Auto-zipping of directories when encrypting, making it easy to send
   folders to friends.
-  Fast underlying C implementations of core miniLock algorithms.
-  Written for ease of use as a Python module, not only as a standalone
   application.
-  No browser, easily scripted, automated or pipelined.
-  "Petnames" allowing you to save IDs as easily-memorable friend names
   or emails
-  *Highly insecure* private key storage, allowing trivial
   encryption/decryption, including iterating through all local private
   keys and attempting decryption with each.
-  Early features for throwaway ultra-high-security addresses.
-  Early features for "vanity" addresses starting or ending in a chosen
   word (warning: may take until heat-death of the universe)

How do I install/use this?
--------------------------

*deadlock* is, at present, a Terminal only application. The best way to
install it is to use pip:

::

    sudo pip install deadlock

..provided that you have the necessary system-level dependencies (C
compiler and supporting libraries), this ought to pull in the required
cryptographic modules from PyPI and build them, then install *deadlock*.

Once installed, *deadlock* will be available as a Python module and also
as a script, ``deadlock``. Try ``deadlock --help`` for guidance on
usage.

*deadlock* will probably work on any platform with a C compiler for the
required modules, but I have no interest in supporting closed,
spyware-rich operating systems like WinMac, so don't ask. If it doesn't
work on those platforms, then you can always fix it and send me a pull
request.

Who do I contact for support or to complain?
--------------------------------------------

Nobody. This software is provided without warranty of any kind. It
works, for me, and I'm pretty sure it's secure, but I'm not going to
certify it as such and you shouldn't use it if you really need security
to protect you from people with the means and motive to harm or imprison
you.
