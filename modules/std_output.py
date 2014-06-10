#!/usr/bin/env python

# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PEframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PEframe. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

def stdoutput(name,size,time,dll,sect,md5,sha1,imph,packer,antidbg,antivm,directory,pefver,date,au_show_pack,au_show_adbg,au_show_avm,au_show_api,au_show_sec,au_show_furl,au_show_meta):
	print "\nShort information"
	print "-"*60
	print "File Name".ljust(18), str(name)
	print "File Size".ljust(18), str(size), "byte"
	print "Compile Time".ljust(18), str(time)
	print "DLL".ljust(18), str(dll)
	print "Sections".ljust(18), str(sect)
	print "Hash MD5".ljust(18), str(md5)
	print "Hash SAH1".ljust(18), str(sha1)
	print "Imphash".ljust(18), str(imph)
	print "Packer".ljust(18), str(packer)
	print "Anti Debug".ljust(18), str(antidbg)
	print "Anti VM".ljust(18), str(antivm)
	print "Directory".ljust(18), str(directory)
	# pefver
	# date
	if au_show_pack:
		len_peid = len(au_show_pack)
		print "\nPacker matched ["+str(len_peid)+"]"
		print "-"*60
		for i in range(0, len_peid):
			print "Packer".ljust(18), str(au_show_pack[i])
	
	if au_show_adbg:
		len_adbg = len(au_show_adbg)
		print "\nAnti Debug discovered ["+str(len_adbg)+"]"
		print "-"*60
		for i in range(0, len_adbg):
			print "Function".ljust(18), str(au_show_adbg[i])

	if au_show_avm:
		len_avm = len(au_show_avm)
		print "\nAnti VM Trick discovered ["+str(len_avm)+"]"
		print "-"*60
		for i in range(0, len_avm):
			print "Trick".ljust(18), str(au_show_avm[i])

	if au_show_api:
		len_api = len(au_show_api)
		print "\nSuspicious API discovered ["+str(len_api)+"]"
		print "-"*60
		for i in range(0, len_api):
			print "Function".ljust(18), str(au_show_api[i])

	if au_show_sec:
		len_sec = len(au_show_sec)
		print "\nSuspicious Sections discovered ["+str(len_sec)+"]"
		print "-"*60
		for i in range(0, len_sec):
			print "Section".ljust(18), str(au_show_sec[i][0])
			print "Hash MD5".ljust(18), str(au_show_sec[i][1])
			print "Hash SHA-1".ljust(18), str(au_show_sec[i][2])

	if au_show_furl and au_show_furl[0]: # File
		len_furl = len(au_show_furl[0])
		print "\nFile name discovered ["+str(len_furl)+"]"
		print "-"*60
		for i in range(0, len_furl):
			print str(au_show_furl[0][i][0]).ljust(18), str(au_show_furl[0][i][1])

	if au_show_furl and au_show_furl[1]: # Url
		len_furl = len(au_show_furl[1])
		print "\nUrl discovered ["+str(len_furl)+"]"
		print "-"*60
		for i in range(0, len_furl):
			print str(au_show_furl[1][i][0]).ljust(18), str(au_show_furl[1][i][1])

	if au_show_meta:
		len_meta = len(au_show_meta)
		print "\nMeta data found ["+str(len_meta)+"]"
		print "-"*60
		for i in range(0, len_meta):
			print str(au_show_meta[i][0]).ljust(18), str(au_show_meta[i][1])

