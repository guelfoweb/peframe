#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from virus_total_apis import PublicApi as VirusTotalPublicApi

def get_result(API_KEY, HASH, full=False):
	vt = VirusTotalPublicApi(API_KEY)
	response = vt.get_file_report(HASH)
	if full:
		return response
	try:
		return {
			"positives": response['results']['positives'], 
			"total": response['results']['total']
			}
	except:
		return {
			"positives": "", 
			"total": ""
			}
