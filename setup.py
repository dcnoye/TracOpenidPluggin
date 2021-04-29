# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 D.C. Noye
#
import os
from setuptools import setup

VERSION = '0.0.1.dev0'

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()


setup(
    name='tracopenid',
    version=VERSION,
    packages=['tracopenid'],
    author='D.C. Noye',
    author_email='dc@noye.org',
    description='Openid for Trac',
    url='https://github.com/dcnoye/tracopenid',
    long_description=README + '\n\n' + CHANGES,
    license='BSD',
    classifiers=[
        "Development Status :: 4 - Alpha",
        "Environment :: Plugins",
        "Environment :: Web Environment",
        "Framework :: Trac",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
    ],
    entry_points={
        'trac.plugins': [
            'tracopenid.main = tracopenid.main',
            'tracopenid.filter = tracopenid.filter',
            ]
    }
)
