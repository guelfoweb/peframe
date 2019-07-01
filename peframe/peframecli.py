#!/usr/bin/env python
# -*- coding: utf-8 -*-

# by Gianni 'guelfoweb' Amato

import os
import sys
import json
import readline
import argparse
from argparse import RawTextHelpFormatter

portable = False
for path in sys.path:
	if os.sep+'peframe'+os.sep+'peframe' in path:
		portable = True
if portable:
	import peframe
	from modules import autocomplete
	from modules import virustotal
	from modules import features
else:
	from peframe import peframe
	from peframe.modules import autocomplete
	from peframe.modules import virustotal
	from peframe.modules import features

# TODO
# [ ] get_data_by_offset

__version__ = peframe.version()

def header(title):
	print ('\n')
	print (''.ljust(80, '-'))
	print (title)
	print (''.ljust(80, '-'))

def interactive_mode():
	header('Interactive mode (press TAB to show commands)')
	help_list = ['?', 'h', 'help', 'ls', 'dir']
	drop_list = ['q!', 'exit', 'quit', 'bye']
	while 1:
		user_input = autocomplete.get_result(cmd_list, "[peframe]>") #input ("[peframe]> ")

		if user_input in help_list:
			print (json.dumps(cmd_list, sort_keys=True, indent=4))
		elif user_input in drop_list:
			print ('goodbye!\n')
			break

		# info
		elif user_input == 'info':
			get_info()
			print ('\n')
		elif user_input == 'yara_plugins':
			yara_plugins_list = []
			for items in result['yara_plugins']:
				for item in items.values():
					yara_plugins_list.append(item)
			print (json.dumps(yara_plugins_list, sort_keys=True, indent=4))
		elif user_input == 'behavior':
			if result['peinfo']:
				print (json.dumps(result['peinfo']['behavior'], sort_keys=True, indent=4))
			if result['docinfo']:
				print (json.dumps(result['docinfo']['behavior'], sort_keys=True, indent=4))
		elif user_input == 'virustotal':
			try:
				vt = virustotal.get_result(peframe.load_config(peframe.path_to_file('config-peframe.json', 'config'))['virustotal'], 
					result['hashes']['md5'], full=True)
				if vt['response_code'] == 200:
					print (json.dumps(cmd_list_select['virustotal'], sort_keys=True, indent=4))
					print ('\nUse \'back\' to return')
					while 1:
						user_input_virustotal = autocomplete.get_result(cmd_list_select['virustotal'], "[peframe/virustotal]>")
						if user_input_virustotal == 'back':
							break
						elif user_input_virustotal == 'permalink':
							print (vt['results']['permalink'])
						elif user_input_virustotal == 'antivirus':
							print (json.dumps(vt['results']['scans'], sort_keys=True, indent=4))
						elif user_input_virustotal == 'scan_date':
							print (vt['results']['scan_date'])
			except:
				print ('VT Query error')

		# directories
		elif user_input == 'directories':
			print (json.dumps(cmd_list_select['directories'], sort_keys=True, indent=4))
			print ('\nUse \'back\' to return')
			while 1:
				user_input_directories = autocomplete.get_result(cmd_list_select['directories'], "[peframe/directories]>")
				if user_input_directories == 'back':
					break
				elif user_input_directories == 'list':
					for item in user_input_directories['directories']:
						print (item)
				elif user_input_directories == 'import':
					print (json.dumps(result['peinfo']['directories']['import'], sort_keys=True, indent=4))
				elif user_input_directories == 'export':
					print (json.dumps(result['peinfo']['directories']['export'], sort_keys=True, indent=4))
				elif user_input_directories == 'debug':
					print (json.dumps(result['peinfo']['directories']['debug'], sort_keys=True, indent=4))
				elif user_input_directories == 'tls':
					print (json.dumps(result['peinfo']['directories']['tls'], sort_keys=True, indent=4))
				elif user_input_directories == 'resources':
					print (json.dumps(result['peinfo']['directories']['resources'], sort_keys=True, indent=4))
				elif user_input_directories == 'relocations':
					print (json.dumps(result['peinfo']['directories']['relocations'], sort_keys=True, indent=4))
				elif user_input_directories == 'sign':
					print (json.dumps(result['peinfo']['directories']['sign'], sort_keys=True, indent=4))

		# sections
		elif user_input == 'sections':
			print (json.dumps(cmd_list_select['sections'], sort_keys=True, indent=4))
			print ('\nUse \'back\' to return')
			while 1:
				user_input_sections = autocomplete.get_result(cmd_list_select['sections'], "[peframe/sections]>")
				if user_input_sections == 'back':
					break
				elif user_input_sections in cmd_list_select['sections']:
					for item in result['peinfo']['sections']['details']:
						if item['section_name'] == user_input_sections:
							print (json.dumps(item, sort_keys=True, indent=4))

		# features
		elif user_input == 'features':
			print (json.dumps(cmd_list_select['features'], sort_keys=True, indent=4))
			print ('\nUse \'back\' to return')
			while 1:
				user_input_features = autocomplete.get_result(cmd_list_select['features'], "[peframe/features]>")
				if user_input_features == 'back':
					break
				elif user_input_features == 'antidbg':
					print (json.dumps(result['peinfo']['features']['antidbg'], sort_keys=True, indent=4))
				elif user_input_features == 'antivm':
					print (json.dumps(result['peinfo']['features']['antivm'], sort_keys=True, indent=4))
				elif user_input_features == 'mutex':
					print (json.dumps(result['peinfo']['features']['mutex'], sort_keys=True, indent=4))
				elif user_input_features == 'packer':
					print (json.dumps(result['peinfo']['features']['packer'], sort_keys=True, indent=4))
				elif user_input_features == 'xor':
					print (json.dumps(result['peinfo']['features']['xor'], sort_keys=True, indent=4))
				elif user_input_features == 'crypto':
					print (json.dumps(result['peinfo']['features']['crypto'], sort_keys=True, indent=4))

		elif user_input == 'breakpoint':
			print (json.dumps(result['peinfo']['breakpoint'], sort_keys=True, indent=4))
		elif user_input == 'hashes':
			print (json.dumps(result['hashes'], sort_keys=True, indent=4))
		elif user_input == 'macro':
			print (result['docinfo']['macro'])
		elif user_input == 'attributes':
			print (json.dumps(result['docinfo']['attributes'], sort_keys=True, indent=4))
		elif user_input == 'metadata':
			print (json.dumps(result['peinfo']['metadata'], sort_keys=True, indent=4))

		# Strings
		elif user_input == 'strings':
			print (json.dumps(cmd_list_select['strings'], sort_keys=True, indent=4))
			print ('\nUse \'back\' to return')
			while 1:
				user_input_strings = autocomplete.get_result(cmd_list_select['strings'], "[peframe/strings]>")
				if user_input_strings == 'back':
					break
				elif user_input_strings == 'list':
					for item in cmd_list_select['strings']:
						print (item)
				elif user_input_strings in cmd_list_select['strings']:
					print (json.dumps(result['strings'][user_input_strings], sort_keys=True, indent=4))

def show_config():
	api_config = peframe.files_to_edit()['api_config']
	string_match = peframe.files_to_edit()['string_match']
	yara_plugins = peframe.files_to_edit()['yara_plugins']
	intro = 'Path(s) to configuration file(s):'
	message = '\napi_config: '+api_config+'\nstring_match: '+string_match+'\nyara_plugins: '+yara_plugins
	return message

def get_info():
	header('File Information (time: ' + str(result['time']) + ')')
	print ("filename".ljust(align, ' '), os.path.basename(result['filename']))
	print ("filetype".ljust(align, ' '), result['filetype'][0:63])
	print ("filesize".ljust(align, ' '), result['filesize'])
	print ("hash sha256".ljust(align, ' '), result['hashes']['sha256'])
	cmd_list.append('hashes')

	print ("virustotal".ljust(align, ' '), str(result['virustotal']['positives']) +'/'+ str(result['virustotal']['total']))
	cmd_list_select.update({"virustotal": ['permalink', 'antivirus', 'scan_date']})

	# peinfo
	if result['peinfo']:
		if hex(result['peinfo']['imagebase']) == '0x400000':
			imagebase = hex(result['peinfo']['imagebase'])
		else:
			imagebase = hex(result['peinfo']['imagebase'])+" *"
		print ("imagebase".ljust(align, ' '), imagebase)
		print ("entrypoint".ljust(align, ' '), hex(result['peinfo']['entrypoint']))
		print ("imphash".ljust(align, ' '), result['peinfo']['imphash'])
		print ("datetime".ljust(align, ' '), result['peinfo']['timestamp'])
		print ("dll".ljust(align, ' '), result['peinfo']['dll'])

		# directories
		if result['peinfo']['directories']:
			directories_list = [k for k,v in result['peinfo']['directories'].items() if v]
			directories_list_temp = list(directories_list)
			if result['peinfo']['directories']['resources']:
				for item in result['peinfo']['directories']['resources']:
					if item['executable'] == True:
						try:
							directories_list_temp.remove('resources')
							directories_list_temp.append('resources *')
						except:
							pass
			if directories_list:
				print ("directories".ljust(align, ' '), ', '.join(directories_list_temp))
				cmd_list.append('directories')
				cmd_list_select.update({"directories": directories_list})

		# sections
		if result['peinfo']['sections']:
			section_list = [items['section_name'] for items in result['peinfo']['sections']['details']]
			section_list_temp = list(section_list)
			for items in result['peinfo']['sections']['details']:
				if items['entropy'] > 6:
					section_list_temp.remove(items['section_name'])
					section_list_temp.append(items['section_name'] + ' *')
			if section_list:
				print ("sections".ljust(align, ' '), ', '.join(section_list_temp))
				cmd_list.append('sections')
				cmd_list_select.update({"sections": section_list})

		# features
		if result['peinfo']['features']:
			features_list = [k for k,v in result['peinfo']['features'].items() if v]
			if features_list:
				print ("features".ljust(align, ' '), ', '.join(features_list))
				cmd_list.append('features')
				cmd_list_select.update({"features": features_list})

		# behavior
		if result['peinfo']['behavior']:
			cmd_list.append('behavior')

		# metadata
		if result['peinfo']['metadata']:
			cmd_list.append('metadata')

		# breakpoint
		if result['peinfo']['breakpoint']:
			cmd_list.append('breakpoint')

	# strings
	if result['strings']:
		strings_list = [k for k,v in result['strings'].items() if v]
		cmd_list.append('strings')
		cmd_list_select.update({"strings": strings_list})

	# docinfo
	if result['docinfo']:
		if result['docinfo']['macro']:
			print ("macro".ljust(align, ' '), True)
			cmd_list.append('macro')
		if result['docinfo']['behavior']:
			cmd_list.append('behavior')
		if result['docinfo']['attributes']:
			cmd_list.append('attributes')

	if result['yara_plugins']:
		cmd_list.append('yara_plugins')

parser = argparse.ArgumentParser(
	prog='peframe',
	description='Tool for static malware analysis.',
	epilog=show_config(),
	formatter_class=RawTextHelpFormatter
)

parser.add_argument("file", help="sample to analyze")
parser.add_argument("-v", "--version", action='version', version='%(prog)s '+str(__version__))
parser.add_argument("-i", "--interactive", help="join in interactive mode", action='store_true', required=False)
parser.add_argument("-x", "--xorsearch", help="search xored string", required=False)
parser.add_argument("-j", "--json", help="export short report in JSON", action='store_true', required=False)
parser.add_argument("-s", "--strings", help="export all strings", action='store_true', required=False)

args = parser.parse_args()

filename = args.file
result = peframe.analyze(filename)

if args.xorsearch:
	print (json.dumps(features.get_xor(filename, search_string=str.encode(args.xorsearch)), sort_keys=True, indent=4))
	sys.exit()

if args.json:
	print (json.dumps(result, sort_keys=True, indent=4))
	sys.exit()

if args.strings:
	print ('\n'.join(result['strings']['dump']))
	sys.exit()

align = 16
cmd_list = ['info', 'strings', 'exit', 'virustotal']
cmd_list_select = {}

if args.interactive:
	json.dumps(get_info(), sort_keys=True, indent=4)
	interactive_mode()
	sys.exit()


get_info()

if result['yara_plugins']:
	header('Yara Plugins')
	for item in result['yara_plugins']:
		for k,v in item.items():
			print (v.replace('_', ' '))


if result['docinfo']:
	if result['docinfo']['behavior']:
		header('Behavior')
		for k, v in result['docinfo']['behavior'].items():
			print (k.ljust(align, ' '), v)
	
	if result['docinfo']['attributes']:
		header('Attributes')
		for item in result['docinfo']['attributes']:
			print (item)

if result['peinfo']:
	if result['peinfo']['behavior']:
		header('Behavior')
		for item in result['peinfo']['behavior']:
			print (item.replace('_', ' '))

	if result['peinfo']['features']['crypto']:
		header('Crypto')
		for item in result['peinfo']['features']['crypto']:
			print (item.replace('_', ' '))

	if result['peinfo']['features']['packer']:
		header('Packer')
		for item in result['peinfo']['features']['packer']:
			print (item.replace('_', ' '))

	if result['peinfo']['features']['xor']:
		header('Xor')
		for k, v in result['peinfo']['features']['xor'].items():
			print (str(k).ljust(align, ' '), v)

	if result['peinfo']['features']['mutex']:
		header('Mutex Api')
		for item in result['peinfo']['features']['mutex']:
			print (item)

	if result['peinfo']['features']['antidbg']:
		header('Anti Debug')
		for item in result['peinfo']['features']['antidbg']:
			print (item)

	if result['peinfo']['features']['antivm']:
		header('Anti VM')
		for item in result['peinfo']['features']['antivm']:
			print (item)

	if result['peinfo']['sections']:
		header('Sections Suspicious')
		found = False
		for item in result['peinfo']['sections']['details']:
			if item['entropy'] > 6:
				print (item['section_name'].ljust(align, ' '), str(item['entropy'])[:4])
				found = True
		if not found:
			print ('For each section the value of entropy is less than 6')

	if result['peinfo']['metadata']:
		header('Metadata')
		for k, v in result['peinfo']['metadata'].items():
			print (k.ljust(align, ' '), v[0:63])

	if result['peinfo']['directories']['import']:
		header('Import function')
		for k, v in result['peinfo']['directories']['import'].items():
			print (k.ljust(align, ' '), len(v))

	if result['peinfo']['directories']['export']:
		header('Export function')
		detect = []
		for item in result['peinfo']['directories']['export']:
			detect.append(item)
		print ("export".ljust(align, ' '), detect)

	if result['peinfo']['directories']['sign']:
		header('Signature')
		for k, v in result['peinfo']['directories']['sign']['details'].items():
			if k != 'hash':
				print (k.ljust(align, ' '), v)


	if result['peinfo']['breakpoint']:
		header('Possibile Breakpoint')
		for item in result['peinfo']['breakpoint']:
			print (item)
	
if result['strings']:
	if result['strings']['ip']:
		header('Ip Address')
		for item in result['strings']['ip']:
			print (item)

	if result['strings']['url']:
		header('Url')
		for item in result['strings']['url']:
			print (item)

	if result['strings']['file']:
		header('File')
		for k, v in result['strings']['file'].items(): 
			print (k.ljust(align, ' '), v)

	if result['strings']['fuzzing']:
		header('Fuzzing')
		for k, v in result['strings']['fuzzing'].items():
			print (k)

sys.exit()