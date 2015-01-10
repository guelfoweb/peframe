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

import os
import pefile
import peutils
from peframe import get_data


# Load PEID userdb.txt database
fn_userdb 	= get_data('userdb.txt')

def get(pe):
	signatures = peutils.SignatureDatabase(fn_userdb)
	matches = signatures.match_all(pe,ep_only = True)
	array = []
	if matches:
		for item in matches:
			# remove duplicate
			if item[0] not in array:
				array.append(item[0])

	return array

