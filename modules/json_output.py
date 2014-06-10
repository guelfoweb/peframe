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

import json

def joutput(name,size,time,dll,sect,md5,sha1,imph,packer,antidbg,antivm,directory,pefver,date,au_show_pack,au_show_adbg,au_show_avm,au_show_api,au_show_sec,au_show_furl,au_show_meta):
	j_short = json.dumps({"filename": name, "filesize": size, "timestamp": time, "dll": dll, "sections": sect, "md5": md5, \
					"sha1": sha1, "imphash": imph, "packer": packer, "antidbg": antidbg, "antivm": antivm, \
					"directory": directory, "pefversion": pefver, "datetime": date})

	if au_show_pack: 
		j_packer  = json.dumps({"name": au_show_pack})
	else:
		j_packer  = ""				

	if au_show_adbg:
		j_antidbg = json.dumps({"name": au_show_adbg})
	else:
		j_antidbg = ""
	
	if au_show_avm:
		j_antivm = json.dumps({"name": au_show_avm})
	else:
		j_antivm = ""
	
	if au_show_api:
		j_apisuspicious = json.dumps({"name": au_show_api})
	else:
		j_apisuspicious = ""
	
	if au_show_sec:
		j_secsuspicious = json.dumps({"name": au_show_sec})
	else:
		j_secsuspicious = ""
	
	if au_show_furl:		
		j_fileurl = json.dumps({"name": au_show_furl})
	else:
		j_fileurl = ""
	
	if au_show_meta:
		j_meta = json.dumps({"name": au_show_meta})
	else:
		j_meta = ""
				
	data = { 'short': j_short, 'show_packer': j_packer, 'show_antidbg': j_antidbg, 'show_antivm': j_antivm, \
			'show_apisuspicious': j_apisuspicious, 'show_secsuspicious': j_secsuspicious, 'show_fileurl': j_fileurl, 'show_meta': j_meta}

	json_output = json.dumps(data, sort_keys=True, indent=0)

	print json_output

