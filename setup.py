#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# This file is part of peframe
# ----------------------------------------------------------------------

from setuptools import setup
from codecs import open  # To use a consistent encoding
from os import path

with open('requirements.txt') as f:
	required = f.read().splitlines()

setup(
	name='peframe',
	version='6.0.3',

	description='peframe is a open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.',
	url='https://github.com/guelfoweb/peframe',

	author='Gianni \'guelfoweb\' Amato',
	author_email='guelfoweb@gmail.com',

	license='GNU',

	# See https://pypi.python.org/pypi?%3Aaction=list_classifiers
	classifiers=[
		# How mature is this project? Common values are
		#   3 - Alpha
		#   4 - Beta
		#   5 - Production/Stable
		'Development Status :: 3 - Production/Stable',

		# Indicate who your project is intended for
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Build Tools',

		# Pick your license as you wish (should match "license" above)
		'License :: OSI Approved :: GNU General Public License (GPL)',

		# Specify the Python versions you support here. In particular, ensure
		# that you indicate whether you support Python 2, Python 3 or both.
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.6',
		'Programming Language :: Python :: 3.7',
	],

	keywords='peframe',

	packages=["peframe", "peframe.modules"],
	package_data={
		'peframe': [
			'config/config-peframe.json',
			'signatures/stringsmatch.json',
			'signatures/yara_plugins/doc/*.yar',
			'signatures/yara_plugins/pdf/*.yar',
			'signatures/yara_plugins/pe/*.yar',
			'signatures/yara_plugins/pe/*.yara',
			], 
	},
	
	install_requires=required,

	entry_points={
		'console_scripts': [
			'peframe=peframe.peframecli',
		],
	},

)
