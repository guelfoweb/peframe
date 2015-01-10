#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PEframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PEframe. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

from setuptools import setup, find_packages
from codecs import open
from os.path import abspath, dirname, join


base_dir = abspath(dirname(__file__))

about = {}
with open(join(base_dir, "peframe", "__about__.py")) as f:
    exec(f.read(), about)

with open(join(base_dir, 'CHANGELOG.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__summary__"],
    long_description=long_description,
    url=about["__uri__"],
    author=about["__author__"],
    author_email=about["__email__"],
    license=about["__license__"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='static malware analysis',
    packages=["peframe", "peframe.modules", "peframe.modules.ordlookup"],
    package_data={
        'peframe': ['signatures/*.txt']
    },
    entry_points={
        'console_scripts': [
            'peframe=peframe.peframe:main',
        ],
    },
)
