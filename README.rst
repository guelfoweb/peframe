=============
PEframe 5.0.1
=============

PEframe is a open source tool to perform static analysis on `Portable Executable <http://en.wikipedia.org/wiki/Portable_Executable>`_ malware and generic suspicious file. It can help malware researchers to detect packer, xor, digital signature, mutex, anti debug, anti virtual machine, suspicious sections and functions, and much more information about the suspicious files.

Documentation will be available soon.

Usage
-----

.. code-block:: bash

    $ peframe <filename>            Short output analysis

    $ peframe --json <filename>     Full output analysis JSON format
    
    $ peframe --strings <filename>  Strings output
    
You can edit `stringsmatch.json <https://github.com/guelfoweb/peframe/blob/master/peframe/signatures/stringsmatch.json>`_ file to configure your fuzzer and virustotal apikey.

Output example
--------------

`Short data example <http://pastebin.com/hrKNtLMN>`_ | `Full data (JSON) example <http://pastebin.com/tpmdsibd/>`_


Install
-------

**Prerequisites**

.. code-block::

    Python 2.7.x

**How to**

To install from PyPI:

 .. code-block:: bash

   # pip install https://github.com/guelfoweb/peframe/archive/master.zip

To install from source:

 .. code-block:: bash

   $ git clone https://github.com/guelfoweb/peframe.git

   $ cd peframe

   # python setup.py install

**Note**

For Windows environment, you need to follow the instructions here: https://github.com/ahupp/python-magic#dependencies (Thanks to `Biagio <https://www.linkedin.com/in/biagiotagliaferro/>`_)

Talk about...
-------------


  * `Multinomial malware classification, research of the Department of Information Security and Communication Technology (NTNU) <https://www.sciencedirect.com/science/article/pii/S1742287618301956>`_ *(SergiiBanin and Geir Olav Dyrkolbotn, Norway)*
  * `SANS DFIR Poster 2016 <http://digital-forensics.sans.org/media/Poster_SIFT_REMnux_2016_FINAL.pdf>`_ *(PEframe was listed in the REMnux toolkits)*
  * `Tools for Analyzing Static Properties of Suspicious Files on Windows <http://digital-forensics.sans.org/blog/2014/03/04/tools-for-analyzing-static-properties-of-suspicious-files-on-windows>`_ *(SANS Digital Forensics and Incident Response, Lenny Zeltser).*
  * `Automated Static and Dynamic Analysis of Malware <http://www.cyberdefensemagazine.com/newsletters/august-2013/index.html#p=26>`_ *(Cyber Defence Magazine, Andrew Browne, Director Malware Lab Lavasoft).*
  * `Suspicious File Analysis with PEframe <https://eforensicsmag.com/download/malware-analysis/>`_ *(eForensics Magazine, Chintan Gurjar)*
  * `CERT FR Security Bulletin <https://www.cert.ssi.gouv.fr/actualite/CERTFR-2014-ACT-030/>`_ *(PEframe was mentioned in the security bulletin CERTFR-2014-ACT-030)*
  * `Infosec CERT-PA Malware Analysis <https://infosec.cert-pa.it/analyze/submission.html>`_ *(PEframe is used in the malware analysis engine of Infosec project, developed by Davide Baglieri)*

Other
-----

This tool is currently maintained by `Gianni 'guelfoweb' Amato <http://guelfoweb.com/>`_, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.
