#!/usr/bin/env python

import sqlite3 as lite

filename="sogei.exe"
filesize="60928 byte"
timestamp="2010-02-04 02:43:43"
dll="No"
sections="3"
md5="a1fb3c5233614b052efc77480d2c0849"
sha1="0dcdd9bd46cb078505eaf4eae28d9898c86c6d1f"
imphash="84708c86646a83b5018f6dc809312365"
packer="Yes"
antidbg="No"
antivm="No"
directory="Import, Resource, Relocation"

show_packer="UPX v0.80 - v0.84, UPX 2.90 (LZMA), UPX -> www.upx.sourceforge.net"
show_antidbg="IsDebuggerPresent"
show_antivm="VM ware"
show_apisuspicious="GetProcAddress, LoadLibraryA, VirtualAlloc, VirtualFree, VirtualProtect"
show_secsuspicious="UPX0, d41d8cd98f00b204e9800998ecf8427e, da39a3ee5e6b4b0d3255bfef95601890afd80709, UPX1, 23e9650927bc7f5c1d321f56ea21525b, c9e88a572d8b5fb2c713d5c48674366f0116da5e"
show_fileurl="KERNEL32.DLL, ntdll.dll"
show_meta="LegalCopyright      \xa9 2006 Microsoft Corporation.  All rights reserved., InternalName        CleanSweep, FileVersion         1, 1, 3, 14, CompanyName         Microsoft Corporation, LegalTrademarks     Microsoft\xae is a registered trademark of Microsoft Corporation., ProductName         2007 Microsoft CleanSweep system, ProductVersion      2, 0, 1, 14, FileDescription     Microsoft CleanSweep, OriginalFilename    cleansweep.exe, Translation         0x0009 0x04b0"


con = lite.connect('db/peframe.db')
con.text_factory = str
cur = con.cursor()    
"""
cur.execute('''
INSERT INTO analysis (id,filename,filesize,timestamp,dll,sections,md5,sha1,imphash,packer,antidbg,antivm,directory,show_packer,show_antidbg,show_antivm,show_apisuspicious,show_secsuspicious,show_fileurl,show_meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	''', (2,filename,filesize,timestamp,dll,sections,md5,sha1,imphash,packer,antidbg,antivm,directory,show_packer,show_antidbg,show_antivm,show_apisuspicious,show_secsuspicious,show_fileurl,show_meta))
con.commit()

"""
cur.execute('''SELECT * FROM analysis''')

all_rows = cur.fetchall()
for row in all_rows:
	for i in range(0, len(row)):
		print row[i]
con.close()








