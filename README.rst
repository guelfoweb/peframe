PEframe
=======

PEframe is a open source tool to perform static analysis on <a href="http://en.wikipedia.org/wiki/Portable_Executable">Portable Executable</a> malware.

Usage
-----

     $ peframe.py malware.exe

     $ peframe.py **[--option]** malware.exe

Options
-------

     --json         Output in json

     --import       Imported function and dll
     --export       Exported function and dll

     --dir-import   Import directory
     --dir-export   Export directory
     --dir-resource Resource directory
     --dir-debug    Debug directory
     --dir-tls      TLS directory

     --strings      Get all strings
     --sections     Sections information
     --dump         Dump all information


Install
-------

**Prerequisites**

     Python 2.6.5 -> 2.7.x

** Install **

     pip install https://github.com/guelfoweb/peframe/archive/master.zip


Example
-------

     $ peframe malware.exe</code>


     Short information
     ------------------------------------------------------------
     File Name          malware.exe
     File Size          935281 byte
     Compile Time       2012-01-29 22:32:28
     DLL                False
     Sections           4
     Hash MD5           cae18bdb8e9ef082816615e033d2d85b
     Hash SAH1          546060ad10a766e0ecce1feb613766a340e875c0
     Imphash            353cf96592db561b5ab4e408464ac6ae
     Detected           Xor, Sign, Packer, Anti Debug, Anti VM
     Directory          Import, Resource, Debug, Relocation, Security

     XOR discovered
     ------------------------------------------------------------
     Key length         Offset (hex)       Offset (dec)
     1                  0x5df4e            384846
     2                  0x5df4e            384846
     4                  0x5df4e            384846
     8                  0x5df4e            384846

     Digital Signature
     ------------------------------------------------------------
     Virtual Address    12A200
     Block Size         4813 byte
     Hash MD5           63b8c4daec26c6c074ca5977f067c21e
     Hash SHA-1         53731a283d0c251f7c06f6d7d423124689873c62

     Packer matched [4]
     ------------------------------------------------------------
     Packer             Microsoft Visual C++ v6.0
     Packer             Microsoft Visual C++ 5.0
     Packer             Microsoft Visual C++
     Packer             Installer VISE Custom

     Anti Debug discovered [9]
     ------------------------------------------------------------
     Anti Debug         FindWindowExW
     Anti Debug         FindWindowW
     Anti Debug         GetWindowThreadProcessId
     Anti Debug         IsDebuggerPresent
     Anti Debug         OutputDebugStringW
     Anti Debug         Process32FirstW
     Anti Debug         Process32NextW
     Anti Debug         TerminateProcess
     Anti Debug         UnhandledExceptionFilter

     Anti VM Trick discovered [2]
     ------------------------------------------------------------
     Trick              Virtual Box
     Trick              VMware trick

     Suspicious API discovered [35]
     ------------------------------------------------------------
     Function           CreateDirectoryA
     Function           CreateFileA
     Function           CreateFileMappingA
     Function           CreateToolhelp32Snapshot
     Function           DeleteFileA
     Function           FindFirstFileA
     Function           FindNextFileA
     Function           GetCurrentProcess
     Function           GetFileAttributesA
     Function           GetFileSize
     Function           GetModuleHandleA
     Function           GetProcAddress
     Function           GetTempPathA
     Function           GetTickCount
     Function           GetUserNameA
     Function           GetVersionExA
     Function           InternetCrackUrlA
     Function           LoadLibraryA
     Function           MapViewOfFile
     Function           OpenProcess
     Function           Process32First
     Function           Process32Next
     Function           RegCloseKey
     Function           RegCreateKeyA
     Function           RegEnumKeyExA
     Function           RegOpenKeyA
     Function           RegOpenKeyExA
     Function           Sleep
     Function           WSAStartup
     Function           WriteFile
     Function           closesocket
     Function           connect
     Function           recv
     Function           send
     Function           socket

     Suspicious Sections discovered [2]
     ------------------------------------------------------------
     Section            .data
     Hash MD5           b896a2c4b2be73b89e96823c1ed68f9c
     Hash SHA-1         523d58892f0375c77e5e1b6f462005ae06cdd0d8
     Section            .rdata
     Hash MD5           41795b402636cb13e2dbbbec031dbb1a
     Hash SHA-1         b674141b34f843d54865a399edfca44c3757df59

     File name discovered [43]
     ------------------------------------------------------------
     Binary             wiseftpsrvs.bin
     Data               ESTdb2.dat
     Data               Favorites.dat
     Data               History.dat
     Data               bookmark.dat
     Data               fireFTPsites.dat
     Data               quick.dat
     Data               site.dat
     Data               sites.dat
     Database           FTPList.db
     Database           sites.db
     Database           NovaFTP.db
     Executable         unleap.exe
     Executable         explorer.exe
     FTP Config         FTPVoyager.ftp
     Library            crypt32.dll
     Library            kernel32.dll
     Library            mozsqlite3.dll
     Library            userenv.dll
     Library            wand.dat
     Library            wininet.dll
     Library            wsock32.dll
     Text               Connections.txt
     Text               ftplist.txt
     Text               signons.txt
     Text               signons2.txt
     Text               signons3.txt

     Url discovered [2]
     ------------------------------------------------------------
     Url                RhinoSoft.com
     Url                http://0uk.net/zaaqw/gate.php

     Meta data found [4]
     ------------------------------------------------------------
     CompiledScript      AutoIt v3 Script
     FileVersion         3, 3, 8, 1
     FileDescription
     Translation         0x0809 0x04b0

(**note:** mixed information as an example)

Credit
------

PEframe include <a href="https://code.google.com/p/pefile/">pefile</a> module written by Ero Carrera and <a href="http://code.google.com/p/pyew/source/browse/plugins/vmdetect.py">Anti Virtual Machine signature</a> written by Joxean Koret.

Talk about...
-------------

  * <a href="http://digital-forensics.sans.org/blog/2014/03/04/tools-for-analyzing-static-properties-of-suspicious-files-on-windows">Tools for Analyzing Static Properties of Suspicious Files on Windows</a> *(SANS Digital Forensics and Incident Response, Lenny Zeltser).*
  * <a href="http://www.cyberdefensemagazine.com/newsletters/august-2013/index.html#p=26">Automated Static and Dynamic Analysis of Malware</a> *(Cyber Defence Magazine, Andrew Browne, Director Malware Lab Lavasoft).*
  * <a href="https://eforensicsmag.com/malware-analysis-2/">Suspicious File Analysis with PEframe</a> *(eForensics Magazine, Chintan Gurjar)*
  * <a href="http://cert.ssi.gouv.fr/site/CERTFR-2014-ACT-030/index.html">Bulletin CERTFR-2014-ACT-030</a> *(PEframe was mentioned in the security bulletin by CERT FR)*


Other
-----

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter <a href="http://twitter.com/guelfoweb">@guelfoweb</a>. Suggestions and criticism are welcome.

Sponsored by **<a href="http://www.securityside.it/">Security Side</a>**.
