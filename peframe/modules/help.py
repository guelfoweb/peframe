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

# About
NAME		= "PEframe"
VERSION		= "4.2"
AUTHOR		= "Author: Gianni 'guelfoweb' Amato"
GITHUB		= "Github: https://github.com/guelfoweb/peframe"
INFO		= NAME+" v."+VERSION+" - Open Source Project\n"+AUTHOR+"\n"+GITHUB

# Help
def help():
	print INFO
	print
	print "Usage"
	print "".ljust(4), "peframe.py malware.exe"
	print "".ljust(4), "peframe.py [--option] malware.exe"
	print
	print "Option"
	print "".ljust(4), "--json".ljust(14), "Output in json"
	print
	print "".ljust(4), "--import".ljust(14), "Imported DLL and functions"
	print "".ljust(4), "--export".ljust(14), "Exported functions"
	print
	print "".ljust(4), "--dir-import".ljust(14), "Import directory"
	print "".ljust(4), "--dir-export".ljust(14), "Export directory"
	print "".ljust(4), "--dir-resource".ljust(14), "Resource directory"
	print "".ljust(4), "--dir-debug".ljust(14), "Debug directory"
	print "".ljust(4), "--dir-tls".ljust(14), "TLS directory"
	print
	print "".ljust(4), "--strings".ljust(14), "Get all strings"
	print "".ljust(4), "--sections".ljust(14), "Sections information"
	print "".ljust(4), "--dump".ljust(14), "Dump all information"

