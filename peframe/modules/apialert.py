#!/usr/bin/env python
# -*- coding: utf-8 -*-

def get_result(pe, strings_match):
	alerts = []
	if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in lib.imports:
				for alert in strings_match:
					if alert and imp.name != None: # remove 'null'
						if imp.name.decode('ascii').startswith(alert):
							alerts.append(imp.name.decode('ascii'))

	return sorted(set(alerts))
