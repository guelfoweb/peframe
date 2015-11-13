========================
PEframe 5.0 Beta version
========================

PEframe is a open source tool to perform static analysis on `Portable Executable <http://en.wikipedia.org/wiki/Portable_Executable>`_ malware and generic suspicious file.

Usage
-----

.. code-block:: bash

    $ peframe <filename>            Short output analysis

    $ peframe --json <filename>     Full output analysis JSON format
    
    $ peframe --strings <filename>  Strings output
    
You can edit `stringsmatch.json <https://github.com/guelfoweb/peframe/blob/5beta/peframe/signatures/stringsmatch.json>`_ file to configure your fuzzer.

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
			"antidbg_info": list,
			"antivm_info": list,
			"apialert_info": list,
			"meta_info": dict,
			"import_function": list,
			"export_function": list,
			"resources_info": list
		}
	}

User output example on `twitter <https://twitter.com/guelfoweb/status/664763793340276736>`_  | JSON output example on `Pastebin <http://pastebin.com/m17vjwF9/>`_.

Install
-------

**Prerequisites**

.. code-block::

    Python 2.7.x

**Install**

from pypi

 .. code-block:: bash

   # pip install https://github.com/guelfoweb/peframe/archive/5beta.zip

from git

 .. code-block:: bash

   $ git clone -b 5beta https://github.com/guelfoweb/peframe.git

   $ cd peframe

   # python setup.py install

Other
-----

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.

Sponsored by `Security Side <http://www.securityside.it/>`_.

