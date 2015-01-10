#!/usr/bin/env python

# ----------------------------------------------------------------------
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

import os, sys
import time, datetime
import json

# sys.path.insert(0, 'modules')

from modules import pefile, peutils, pecore, stdoutput, help


def is_pe(filename):
	try:
		global pe
		pe = pefile.PE(filename)
		return True
	except:
		print "Error: invalid file"
		exit(0)

def autoanalysis(pe, filename, json=False):
	if json:
		print pecore.get_info(pe, filename), \
			pecore.get_cert(pe), \
			pecore.get_packer(pe), \
			pecore.get_antidbg(pe), \
			pecore.get_antivm(filename), \
			pecore.get_xor(filename), \
			pecore.get_apialert(pe), \
			pecore.get_secalert(pe), \
			pecore.get_fileurl(filename), \
			pecore.get_meta(pe)

	else:
		stdoutput.show_auto(
			pecore.get_info(pe, filename), \
			pecore.get_cert(pe), \
			pecore.get_packer(pe), \
			pecore.get_antidbg(pe), \
			pecore.get_antivm(filename), \
			pecore.get_xor(filename), \
			pecore.get_apialert(pe), \
			pecore.get_secalert(pe), \
			pecore.get_fileurl(filename), \
			pecore.get_meta(pe))



#______________________Main______________________

def main():

	# Manage Args
	if len(sys.argv) == 1 or len(sys.argv) > 3:
		help.help()
		exit(0)

	if len(sys.argv) == 2 and sys.argv[1] == "-h" or sys.argv[1] == "--help":
		help.help()
		exit(0)

	if len(sys.argv) == 2 and sys.argv[1] == "-v" or sys.argv[1] == "--version":
		print help.VERSION
		exit(0)

	# Auto Analysis
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		is_pe(filename)
		autoanalysis(pe, filename)

	# Options
	if len(sys.argv) == 3:
		option   = sys.argv[1]
		filename = sys.argv[2]
		is_pe(filename)

		if option == "--json":
			autoanalysis(pe, filename, json=True); exit(0)
			
		elif option == "--import":
			stdoutput.show_import(pe); exit(0)
		elif option == "--export":
			stdoutput.show_export(pe); exit(0)
			
		elif option == "--dir-import":
			stdoutput.show_directory(pe, "import"); exit(0)
		elif option == "--dir-export":
			stdoutput.show_directory(pe, "export"); exit(0)
		elif option == "--dir-resource":
			stdoutput.show_directory(pe, "resource"); exit(0)
		elif option == "--dir-debug":
			stdoutput.show_directory(pe, "debug"); exit(0)
		elif option == "--dir-tls":
			stdoutput.show_directory(pe, "tls"); exit(0)
			
		elif option == "--strings":
			print pecore.get_strings(filename); sys.exit(0)
		elif option == "--sections":
			print pecore.get_sections(pe); sys.exit(0)
		elif option == "--dump":
			print pecore.get_dump(pe); sys.exit(0)
		else:
			help.help()


if __name__ == '__main__':
	main()