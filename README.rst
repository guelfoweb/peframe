=============
PEframe 6.0.0
=============

PEframe is a open source tool to perform static analysis on `Portable Executable <http://en.wikipedia.org/wiki/Portable_Executable>`_ malware and generic suspicious file. It can help malware researchers to detect packer, xor, digital signature, mutex, anti debug, anti virtual machine, suspicious sections and functions, macro and much more information about the suspicious files.

Usage
-----

.. code-block:: bash

    python3 peframe-cli.py <filename>     Short output analysis

    python3 peframe-cli.py -i <filename>  Interactive mode

    python3 peframe-cli.py -j <filename>  Full output analysis JSON format
    
    python3 peframe-cli.py -s <filename>  Strings output
    
You can edit `config-peframe.json <https://github.com/guelfoweb/peframe/blob/master/config/config-peframe.json>`_ file in "config" folder to configure virustotal API key.




Install
-------

**Prerequisites**

.. code-block::

    python >= 3.6.6
    pip3
    libssl-dev
    swig

**Download**

.. code-block::

   git clone https://github.com/guelfoweb/peframe.git

**Install using PyPI**

.. code-block::

   pip3 install -r requirements.txt

**Install on Debian/Ubuntu**

.. code-block::

   bash install.sh

How to work
-----------

**MS Office (macro) document analysis**

.. image:: https://asciinema.org/a/mbLd5dChz9iI8eOY15fC2423X.svg
   :target: https://asciinema.org/a/mbLd5dChz9iI8eOY15fC2423X?autoplay=1


**PE file analysis**

.. image:: https://asciinema.org/a/P6ANqp0bHV0nFsuJDuqD7WQD7.svg
   :target: https://asciinema.org/a/P6ANqp0bHV0nFsuJDuqD7WQD7?autoplay=1


Talk about...
-------------


  * `Multinomial malware classification, research of the Department of Information Security and Communication Technology (NTNU) <https://www.sciencedirect.com/science/article/pii/S1742287618301956>`_ *(SergiiBanin and Geir Olav Dyrkolbotn, Norway)*
  * `SANS DFIR Poster 2016 <http://digital-forensics.sans.org/media/Poster_SIFT_REMnux_2016_FINAL.pdf>`_ *(PEframe was listed in the REMnux toolkits)*
  * `Tools for Analyzing Static Properties of Suspicious Files on Windows <http://digital-forensics.sans.org/blog/2014/03/04/tools-for-analyzing-static-properties-of-suspicious-files-on-windows>`_ *(SANS Digital Forensics and Incident Response, Lenny Zeltser).*
  * `Automated Static and Dynamic Analysis of Malware <http://www.cyberdefensemagazine.com/newsletters/august-2013/index.html#p=26>`_ *(Cyber Defence Magazine, Andrew Browne, Director Malware Lab Lavasoft).*
  * `Suspicious File Analysis with PEframe <https://eforensicsmag.com/download/malware-analysis/>`_ *(eForensics Magazine, Chintan Gurjar)*
  * `CERT FR Security Bulletin <https://www.cert.ssi.gouv.fr/actualite/CERTFR-2014-ACT-030/>`_ *(PEframe was mentioned in the security bulletin CERTFR-2014-ACT-030)*
  * `Infosec CERT-PA Malware Analysis <https://infosec.cert-pa.it/analyze/submission.html>`_ *(PEframe is used in the malware analysis engine of Infosec project)*

Other
-----

This tool is currently maintained by `Gianni 'guelfoweb' Amato <http://guelfoweb.com/>`_, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.
