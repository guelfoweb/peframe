#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
from oletools.olevba3 import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

def get_result(filename):
	try:
		behavior = {}

		vbaparser = VBA_Parser(filename)

		if vbaparser.detect_vba_macros():
			results = vbaparser.analyze_macros()
			for item in results:
				details = re.sub(r'\(.*\)', '', str(item[2]))
				details = details.replace('strings', 'str')
				details = re.sub(r' $', '', details)
				if item[0] == 'AutoExec':
					behavior.update({item[1]: details})
				if item[0] == 'Suspicious':
					behavior.update({item[1]: details})

			macro = vbaparser.reveal()
			attributes = re.findall(r'Attribute VB.*', macro, flags=re.MULTILINE)
			macro = re.sub(r'Attribute VB.*', '', macro)
			
			return {"behavior": behavior, "macro": macro, "attributes": attributes}
			vbaparser.close()
	except:
		return {}
