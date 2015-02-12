#!/usr/bin/env python
from setuptools import setup

# do some feature detection to see what extra packages need to be installed
install_requires = []
try:
    from ssl import match_hostname, CertificateError
except ImportError:
    install_requires.append('backports.ssl_match_hostname')

import unittest
try:
    unittest.TestCase.assertIn
except AttributeError:
    install_requires.append('unittest2')

setup(
    name="stashward",
    version='0.1.1',
    author='Matt Johnson',
    author_email='mdj2@pdx.edu',
    description="A log formatter and handler for Python that implements the (poorly specified) logstash-forwarder protocol.",
    packages=['stashward'],
    zip_safe=False,
    install_requires=install_requires,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.6',
    ],
)
