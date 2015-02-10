#!/usr/bin/env python
from setuptools import setup
import sys

setup(
    name="stashward",
    version='0.0.0',
    author='Matt Johnson',
    author_email='mdj2@pdx.edu',
    description="A log formatter and handler for Python that implements the (poorly specified) logstash-forwarder protocol.",
    packages=['stashward'],
    zip_safe=False,
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
)
