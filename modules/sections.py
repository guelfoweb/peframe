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

import pefile
import peutils

def get(pe):
	array = []
	for section in pe.sections:
		section.get_entropy()
		if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
			suspicious = True
		else:
			suspicious = False
		
		scn  = section.Name
		md5  = section.get_hash_md5()
		sha1 = section.get_hash_sha1()
		spc  = suspicious
		va   = hex(section.VirtualAddress)
		vs   = hex(section.Misc_VirtualSize)
		srd  = section.SizeOfRawData

		array.append([scn, md5, sha1, spc, va, vs, srd])

	return array

