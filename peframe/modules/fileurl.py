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

import re
import json
import string
import stringstat

def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False

def get(filename, strings_match):
	strings_info = json.loads(stringstat.get(filename))
	strings_list = strings_info['content']
	ip_list = []
	file_list = []
	filetype_dict = {}
	url_list = []
	fuzzing_dict = {}
	apialert_list = []
	antidbg_list = []

	# Get filetype and fuzzing
	file_type = strings_match['filetype'].items()
	fuzzing_list = strings_match['fuzzing'].items()

	# Strings analysis
	for string in strings_list:
		# URL list
		urllist = re.findall(r'((smb|srm|ssh|ftps?|file|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', string, re.MULTILINE)
		if urllist:
			for url in urllist:
				url_list.append(url[0])

		# IP list
		iplist = re.findall(r'[0-9]+(?:\.[0-9]+){3}', string, re.MULTILINE)
		if iplist:
			for ip in iplist:
				if valid_ip(str(ip)) and not re.findall(r'[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0', str(ip)):
					ip_list.append(str(ip))

		# FILE list
		fname = re.findall("(.+(\.([a-z]{2,3}$)|\/.+\/|\\\.+\\\))+", string, re.IGNORECASE | re.MULTILINE)
		if fname:
			for word in fname:
				word = filter(None, word[0])
				file_list.append(word)

	# Purge list
	ip_list = filter(None, list(set([item for item in ip_list])))
	url_list = filter(None, list(set([item for item in url_list])))
	
	# Initialize filetype
	for key, value in file_type:
		filetype_dict[key] = []

	# Search for valid filename
	array_tmp = []
	for file in file_list:
		for key, value in file_type:
			match = re.findall("\\"+value+"$", file, re.IGNORECASE | re.MULTILINE)
			if match and file.lower() not in array_tmp and len(file) > 4: 
				filetype_dict[key].append(file)
				array_tmp.append(file.lower())
	
	# Remove empty key filetype
	for key, value in filetype_dict.items():
		if not filetype_dict[key]:
			del filetype_dict[key]

	# Initialize fuzzing
	for key, value in fuzzing_list:
		fuzzing_dict[key] = []

	# Strings analysis for fuzzing
	array_tmp = []
	for string in strings_list:
		for key, value in fuzzing_list:
			fuzz_match = re.findall(value, string, re.IGNORECASE | re.MULTILINE)
			if fuzz_match and string.lower() not in array_tmp:
				fuzzing_dict[key].append(string)
				array_tmp.append(string.lower())

	# Remove empty key filetype
	for key, value in filetype_dict.items():
		if not filetype_dict[key]:
			del filetype_dict[key]

	# Remove empty key fuzzing
	for key, value in fuzzing_list:
		if not fuzzing_dict[key]:
			del fuzzing_dict[key]
	
	return {"file":  filetype_dict, "url": url_list, "ip": ip_list, "fuzzing": fuzzing_dict}
		
