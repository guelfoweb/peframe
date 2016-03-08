#!/usr/bin/env python

# ----------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2015 Gianni Amato
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ----------------------------------------------------------------------

# About
NAME	= "PEframe"
VERSION	= "5.0.1"
LICENSE = "MIT"
AUTHOR	= "Author: Gianni 'guelfoweb' Amato"
GITHUB	= "Github: https://github.com/guelfoweb/peframe"
INFO	= NAME+" v."+VERSION+" - Open Source Project - "+LICENSE+" LICENSE\n"+AUTHOR+"\n"+GITHUB

# Help
def help():
	print INFO
	print
	print "Usage"
	print "".ljust(4), "peframe <filename>".ljust(20), "Short output analysis"
	print
	print "Options"
	print "".ljust(4), "--json".ljust(20), "Full output analysis JSON format"
	print "".ljust(4), "--strings".ljust(20), "Strings output"
	print
	print "Examples"
	print "".ljust(4), "peframe malware.exe"
	print "".ljust(4), "peframe --json malware.exe"
	print "".ljust(4), "peframe --strings malware.exe"
	print
	print "Use 'stringsmatch.json' to configure your fuzzer."

