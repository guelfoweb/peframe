#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

def path_to_file(filename, folder):
	_ROOT = os.path.abspath(os.path.dirname(__file__))
	return os.path.join(_ROOT, folder, filename).replace('modules/', '')

def load_config(config_file):
	with open(config_file) as conf:
		data = json.load(conf)
	return data

def files_to_edit():
	path = {
		"api_config": path_to_file('config-peframe.json', 'config'),
		"string_match": path_to_file('stringsmatch.json', 'signatures'),
		"yara_plugins": path_to_file('yara_plugins', 'signatures')
	}
	return path