from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'CHANGELOG.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='peframe',

    version='5.0.1',

    description='PEframe is a open source tool to perform static analysis on Portable Executable malware.',
    long_description=long_description,

    url='https://github.com/guelfoweb/peframe',

    author='Gianni Amato',
    author_email='guelfoweb@gmail.com',

    license='MIT',

    classifiers=[
        'Development Status :: 5 - Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='static malware analysis',

    packages=["peframe", "peframe.modules", "peframe.modules.ordlookup"],

    package_data={
        'peframe': ['signatures/*.*']
    },

    entry_points={
        'console_scripts': [
            'peframe=peframe.peframe:main',
        ],
    },
)
