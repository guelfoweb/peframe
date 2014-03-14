PEframe
=======

PEframe is a open source tool to perform static analysis on <a href="http://en.wikipedia.org/wiki/Portable_Executable">(Portable Executable)</a> malware.

**Usage**

<code>$ peframe.py malware.exe</code>

<code>$ peframe.py **[--option]** malware.exe</code>

**Options**

<pre>
     --import       Imported function and dll
     --export       Exported function and dll

     --dir-import   Import directory
     --dir-export   Export directory
     --dir-resource Resource directory
     --dir-debug    Debug directory
     --dir-tls      TLS directory
     --dir-reloc    Relocation directory

     --strings      Get all strings
     --sections     Sections information
     --dump         Dump all information
</pre>

Install
=======
**Prerequisites**

<code>Python 2.6.5 -> 2.7.x</code>

**Download**

<code>$ git clone https://github.com/guelfoweb/peframe.git</code>

or <b><a href="https://github.com/guelfoweb/peframe/archive/master.zip" alt="peframe-master.zip" title="peframe-master.zip">Download Zip</a></b> and extract <code>peframe</code> folder.

Example
=======

<code>$ python peframe.py malware.exe</code>

<pre>
Short information
------------------------------------------------------------
File Name          malware.exe
File Size          935281 byte
Compile Time       2012-01-29 22:32:28
DLL                No
Sections           4
Hash MD5           cae18bdb8e9ef082816615e033d2d85b
Hash SAH1          546060ad10a766e0ecce1feb613766a340e875c0
Packer             Yes
Anti Debug         Yes
Anti VM            Yes
Directory          Import, Resource

Packer matched [3]
------------------------------------------------------------
Packer             Microsoft Visual C++ 8
Packer             VC8 -> Microsoft Corporation
Packer             Microsoft Visual C++ 8

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
Text               Connections.txt
Data               ESTdb2.dat
Database           FTPList.db
FTP Config         FTPVoyager.ftp
Data               Favorites.dat
Data               History.dat
Database           NovaFTP.db
Data               QData.dat
Data               \History.dat
Data               \Quick.dat
Data               \Sites.dat
Data               \sm.dat
Data               addrbk.dat
Library            advapi32.dll
Data               bookmark.dat
Library            crypt32.dll
Library            explorer.exe
Data               fireFTPsites.dat
Text               ftplist.txt
Library            kernel32.dll
Library            mozsqlite3.dll
Library            msi.dll
Library            netapi32.dll
Library            nss3.dll
Library            ole32.dll
Library            pstorec.dll
Data               quick.dat
Library            shell32.dll
Library            shlwapi.dll
Text               signons.txt
Text               signons2.txt
Text               signons3.txt
Data               site.dat
Data               sites.dat
Database           sites.db
Library            sqlite3.dll
Executable         unleap.exe
Library            user32.dll
Library            userenv.dll
Library            wand.dat
Library            wininet.dll
Binary             wiseftpsrvs.bin
Library            wsock32.dll

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
</pre>
<i>(**note:** mixed information as an example)</i>

Credit
======

PEframe include <a href="https://code.google.com/p/pefile/">pefile</a> module written by Ero Carrera and <a href="http://code.google.com/p/pyew/source/browse/plugins/vmdetect.py">Anti Virtual Machine signature</a> written by Joxean Koret.

**Talk about...**

<ul>
<li><a href="http://digital-forensics.sans.org/blog/2014/03/04/tools-for-analyzing-static-properties-of-suspicious-files-on-windows">Tools for Analyzing Static Properties of Suspicious Files on Windows</a> <i>(SANS Digital Forensics and Incident Response, Lenny Zeltser).</i></li>
<li><a href="http://www.cyberdefensemagazine.com/newsletters/august-2013/index.html#p=26">Automated Static and Dynamic Analysis of Malware</a> <i>(Cyber Defence Magazine, Andrew Browne, Director Malware Lab Lavasoft).</i></li>
<li><a href="https://eforensicsmag.com/malware-analysis-2/">Suspicious File Analysis with PEframe</a> <i>(eForensics Magazine, Chintan Gurjar)</i></li>
</ul>

Other
=====

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter <a href="http://twitter.com/guelfoweb">@guelfoweb</a>. Suggestions and criticism are welcome.

Sponsored by **<a href="http://www.securityside.it/">Security Side</a>**.
