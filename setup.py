import deadlock
import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), "README.txt")) as readme:
    long_description = readme.read()

setup(
    name='deadlock',
    description="A Python implementation of minilock.io, plus some additional features.",
    long_description=long_description,
    version=deadlock.__version__,
    url="https://github.com/cathalgarvey/deadlock",
    author="Cathal Garvey",
    author_email="cathalgarvey@cathalgarvey.me",
    maintainer="Cathal Garvey",
    maintainer_email="cathalgarvey@cathalgarvey.me",
    license="GNU Affero General Public License v3",
    packages = ['deadlock'],
    install_requires = [
        'base58',
        'PyNaCl',
        'scrypt',
        'pyblake2'
        ],
    entry_points = {
        'console_scripts': ['deadlock=deadlock:main']
    },
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4"
    ]
)
