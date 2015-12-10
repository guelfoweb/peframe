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

import simplejson
import urllib
import urllib2

def vtcheck(apikey, tosearch):
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": tosearch,
				  "apikey": apikey}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	return json

def get(tosearch, strings_match):
	apikey = strings_match['virustotal']['apikey']
	if apikey:
		response = vtcheck(apikey, tosearch)
		response = simplejson.loads(response)
		if response['response_code'] == 1:
			scan_date = response['scan_date']
			permalink = response['permalink']
			positives = response['positives']
			total = response['total']
			
			return {"scan_date":  scan_date, "total": total, "positives": positives, "permalink": permalink}
		else:
			return {}
	else:
		return {}

