=======
peframe
=======

peframe is a open source tool to perform static analysis on `Portable Executable <http://en.wikipedia.org/wiki/Portable_Executable>`_ malware and generic suspicious file. It can help malware researchers to detect packer, xor, digital signature, mutex, anti debug, anti virtual machine, suspicious sections and functions, macro and much more information about the suspicious files.


Install
-------

**Download**

.. code-block::

   sudo apt install git
   git clone https://github.com/guelfoweb/peframe.git
   cd peframe
   
**Installation script for Ubuntu**

.. code-block::

   sudo bash install.sh

**Installation (prerequisites required)**

.. code-block::

    sudo python3 setup.py install


**Prerequisites**

The following prerequisites are required to be installed on your system before you can install and use peframe.

.. code-block::

    python >= 3.6.6
    pyton3-pip
    libssl-dev
    swig


Usage
-----

peframe -h

.. code-block::

    peframe filename            Short output analysis
    peframe -i filename         Interactive mode
    peframe -j filename         Full output analysis JSON format
    peframe -x STRING filename  Search xored string
    peframe -s filename         Strings output
    

**Note**

You can edit "config-peframe.json" file in "config" folder to configure virustotal API key. After installation you can use "peframe -h" to find api_config path.


How to work
-----------

**MS Office (macro) document analysis with peframe 6.0.1**

.. image:: https://asciinema.org/a/mbLd5dChz9iI8eOY15fC2423X.svg
   :target: https://asciinema.org/a/mbLd5dChz9iI8eOY15fC2423X?autoplay=1


**PE file analysis with peframe 6.0.1**

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
