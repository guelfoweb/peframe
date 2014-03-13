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

**Download (v.3.0 rc1)**

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

Suspicious API discovered [37]
------------------------------------------------------------
Function           CopyFileW
Function           CreateDirectoryW
Function           CreateFileW
Function           CreateProcessAsUserW
Function           CreateProcessW
Function           DeleteFileW
Function           DeviceIoControl
Function           EnumProcesses
Function           ExitThread
Function           FindFirstFileW
Function           FindNextFileW
Function           FindResourceW
Function           FindWindowExW
Function           FindWindowW
Function           FtpGetFileSize
Function           FtpOpenFileW
Function           GetCommandLineW
Function           GetComputerNameW
Function           ReadProcessMemory
Function           RegCloseKey
Function           RegCreateKeyExW
Function           RegDeleteKeyW
Function           RegDeleteValueW
Function           RegEnumKeyExW
Function           RegOpenKeyExW
Function           SetKeyboardState
Function           ShellExecuteExW
Function           ShellExecuteW
Function           Sleep
Function           TerminateProcess
Function           UnhandledExceptionFilter
Function           VirtualAlloc
Function           VirtualAllocEx
Function           VirtualFree
Function           VirtualFreeEx
Function           WriteFile
Function           WriteProcessMemory

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
File name          Connections.txt
File name          ESTdb2.dat
File name          FTPList.db
File name          FTPVoyager.ftp
File name          Favorites.dat
File name          History.dat
File name          NovaFTP.db
File name          QData.dat
File name          \History.dat
File name          \Quick.dat
File name          \Sites.dat
File name          \sm.dat
File name          addrbk.dat
File name          advapi32.dll
File name          bookmark.dat
File name          crypt32.dll
File name          explorer.exe
File name          fireFTPsites.dat
File name          ftplist.txt
File name          kernel32.dll
File name          mozsqlite3.dll
File name          msi.dll
File name          netapi32.dll
File name          nss3.dll
File name          ole32.dll
File name          pstorec.dll
File name          quick.dat
File name          shell32.dll
File name          shlwapi.dll
File name          signons.txt
File name          signons2.txt
File name          signons3.txt
File name          site.dat
File name          sites.dat
File name          sites.db
File name          sqlite3.dll
File name          unleap.exe
File name          user32.dll
File name          userenv.dll
File name          wand.dat
File name          wininet.dll
File name          wiseftpsrvs.bin
File name          wsock32.dll

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
<li><a href="https://eforensicsmag.com/malware-analysis-2/">Suspicious File Analysis with PEFrame</a> <i>(eForensics Magazine, Chintan Gurjar)</i></li>
</ul>

Other
=====

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter <a href="http://twitter.com/guelfoweb">@guelfoweb</a>. Suggestions and criticism are welcome.

Sponsored by **<a href="http://www.securityside.it/">Security Side</a>**.
