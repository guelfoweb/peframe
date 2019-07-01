#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys

def get_wanted_chars():
	wanted_chars = ["\0"]*256

	for i in range(32, 127):
		wanted_chars[i] = chr(i)

	wanted_chars[ord("\t")] = "\t"
	return "".join(wanted_chars)

def get_wanted_chars_unicode():
	wanted_chars = ["\0"]*256

	for i in range(32, 127):
		wanted_chars[i] = chr(i)

	wanted_chars[ord("\t")] = "\t"
	return "".join(wanted_chars)

def get_result(filename):
	results = []

	THRESHOLD = 4

	for s in open(filename, errors="ignore").read().translate(get_wanted_chars()).split("\0"):
		if len(s) >= THRESHOLD:
			results.append(s)

	return results
