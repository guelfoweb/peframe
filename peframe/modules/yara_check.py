#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from os import walk
import yara

def yara_match_from_file(fileyara, filename):
	matches = []
	rules = yara.compile(fileyara)

	# serialize matches
	try:
		for match in rules.match(filename):
			matches.append(str(match))
	except: # fix yara.Error: internal error: 30
		pass

	return matches

def yara_match_from_folder(folder_yara, filename, exclude=[]):
	matches = []
	#for fileyara in yara_files:
	for (dirpath, dirnames, filenames) in walk(folder_yara):
		for f in filenames:
			if str(f).endswith('.yar') and str(f) not in exclude:
				path_to_file_yara = str(dirpath)+os.sep+str(f)

				try:
					rules = yara.compile(path_to_file_yara)
					
					# serialize matches
					for match in rules.match(filename, timeout=60):
						matches.append({f: str(match)})
				except:
					pass


	return matches
