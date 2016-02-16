===========
PEframe 5.0
===========

PEframe is a open source tool to perform static analysis on `Portable Executable <http://en.wikipedia.org/wiki/Portable_Executable>`_ malware and generic suspicious file. It can help malware researchers to detect packer, xor, digital signature, mutex, anti debug, anti virtual machine, suspicious sections and functions, and much more information about the suspicious files.

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

Simple schema
-------------

.. code-block::

	{
		"peframe_ver": string,
		"file_type": string,
		"file_name": string,
		"file_size": int,
		"hash": dict,
		"file_found": dict,
		"url_found": list,
		"ip_found": list,
		"virustotal": dict,
		"fuzzing": list,
		"pe_info": {
			"compile_time": string, 
			"dll": bool,
			"sections_number": int,
			"sections_info": list,
			"xor_info": dict,
			"detected": list,
			"directories": list,
			"sign_info": dict,
			"packer_info": list,
			"mutex_info": list,
			"antidbg_info": list,
			"antivm_info": list,
			"apialert_info": list,
			"meta_info": dict,
			"import_function": list,
			"export_function": list,
			"resources_info": list
		}
	}

Install
-------

**Prerequisites**

.. code-block::

    Python 2.7.x

**Install**

To install from PyPI:

 .. code-block:: bash

   # pip install https://github.com/guelfoweb/peframe/archive/master.zip

To install from source:

 .. code-block:: bash

   $ git clone https://github.com/guelfoweb/peframe.git

   $ cd peframe

   # python setup.py install


Talk about...
-------------

  * `Tools for Analyzing Static Properties of Suspicious Files on Windows <http://digital-forensics.sans.org/blog/2014/03/04/tools-for-analyzing-static-properties-of-suspicious-files-on-windows>`_ *(SANS Digital Forensics and Incident Response, Lenny Zeltser).*
  * `Automated Static and Dynamic Analysis of Malware <http://www.cyberdefensemagazine.com/newsletters/august-2013/index.html#p=26>`_ *(Cyber Defence Magazine, Andrew Browne, Director Malware Lab Lavasoft).*
  * `Suspicious File Analysis with PEframe <https://eforensicsmag.com/download/malware-analysis/>`_ *(eForensics Magazine, Chintan Gurjar)*
  * `Bulletin CERTFR-2014-ACT-030 <http://cert.ssi.gouv.fr/site/CERTFR-2014-ACT-030/index.html>`_ *(PEframe was mentioned in the security bulletin by CERT FR)*
  * `SANS DFIR Poster 2016 <http://digital-forensics.sans.org/media/Poster_SIFT_REMnux_2016_FINAL.pdf>`_ *(PEframe was listed in the REMnux toolkits)*

Other
-----

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.

Sponsored by `Security Side <http://www.securityside.it/>`_.

