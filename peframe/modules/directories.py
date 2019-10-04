#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pefile

def get_import(pe):
	array = []
	library = []
	libdict = {}

	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll = entry.dll.decode('ascii')
		for imp in entry.imports:
			address = imp.address
			try:
				function = imp.name.decode('ascii')
			except:
				function = str(imp.name) #.decode('ascii')
			else:
				pass
			
			if dll not in library:
				library.append(dll)
			array.append({
				"library": dll, 
				"offset": address,
				"function": function
				})
	
	for key in library:
		libdict[key] = []
	
	for lib in library:
		for item in array:
			if lib == item['library']:
				libdict[lib].append({"offset": item['offset'], "function": item['function']})
	return libdict

def get_export(pe):
	array = []
	try:
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			# No dll
			address = pe.OPTIONAL_HEADER.ImageBase + exp.address
			function = exp.name.decode('ascii')
			array.append({"offset": address, "function": function})
	except:
		pass
	return array

def get_debug(pe):
	DEBUG_TYPE = {
			"IMAGE_DEBUG_TYPE_UNKNOWN"   : 0,
			"IMAGE_DEBUG_TYPE_COFF"      : 1,
			"IMAGE_DEBUG_TYPE_CODEVIEW"  : 2,
			"IMAGE_DEBUG_TYPE_FPO"       : 3,
			"IMAGE_DEBUG_TYPE_MISC"      : 4,
			"IMAGE_DEBUG_TYPE_EXCEPTION" : 5,
			"IMAGE_DEBUG_TYPE_FIXUP"     : 6,
			"IMAGE_DEBUG_TYPE_BORLAND"   : 9,
			}
	
	result = {}
	# https://github.com/mnemonic-no/dnscache/blob/master/tools/pdbinfo.py
	for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		if d.name == "IMAGE_DIRECTORY_ENTRY_DEBUG": break

	if not d or d.name != "IMAGE_DIRECTORY_ENTRY_DEBUG":
		return result

	debug_directories = pe.parse_debug_directory(d.VirtualAddress, d.Size)
	for debug_directory in debug_directories:
		if debug_directory.struct.Type == DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"]:
			result.update({
				"PointerToRawData": debug_directory.struct.PointerToRawData, 
				"size": debug_directory.struct.SizeOfData
				})
			return result
	return result

def get_relocations(pe):
	result = {}
	for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		if d.name == "IMAGE_DIRECTORY_ENTRY_BASERELOC": break

	if not d or d.name != "IMAGE_DIRECTORY_ENTRY_BASERELOC":
		return result

	result.update({"VirtualAddress": d.VirtualAddress, "Size": d.Size})
	reloc_directories = pe.parse_relocations_directory(d.VirtualAddress, d.Size)
	result.update({"count": len(reloc_directories)})
	i = 0
	my_items = {}
	for items in reloc_directories:
		i = i+1
		for item in items.entries:
			my_items.update({"reloc_"+str(i): len(items.entries)})
	result.update({"details": my_items})
	return result

def get_tls(pe):
	result = {}
	for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		if d.name == "IMAGE_DIRECTORY_ENTRY_TLS": break

	if not d or d.name != "IMAGE_DIRECTORY_ENTRY_TLS":
		return result

	tls_directories = pe.parse_directory_tls(d.VirtualAddress, d.Size).struct
	"""
	[IMAGE_TLS_DIRECTORY]
	0x0        0x0   StartAddressOfRawData:         0x905A4D  
	0x4        0x4   EndAddressOfRawData:           0x3       
	0x8        0x8   AddressOfIndex:                0x4       
	0xC        0xC   AddressOfCallBacks:            0xFFFF    
	0x10       0x10  SizeOfZeroFill:                0xB8      
	0x14       0x14  Characteristics:               0x0 
	"""
	result.update({
		"StartAddressOfRawData": tls_directories.StartAddressOfRawData,
		"EndAddressOfRawData": tls_directories.EndAddressOfRawData,
		"AddressOfIndex": tls_directories.AddressOfIndex,
		"AddressOfCallBacks": tls_directories.AddressOfCallBacks,
		"SizeOfZeroFill": tls_directories.SizeOfZeroFill,
		"Characteristics": tls_directories.Characteristics,
		})

	return result

import re
import binascii
def get_resources(pe):
	res_array = []
	try:
		'''
		# resource types					# description
		RT_CURSOR = 1						# Hardware-dependent cursor resource.
		RT_BITMAP = 2						# Bitmap resource.
		RT_ICON = 3							# Hardware-dependent icon resource.
		RT_MENU = 4							# Menu resource.
		RT_DIALOG = 5						# Dialog box.
		RT_STRING = 6						# String-table entry.
		RT_FONTDIR = 7						# Font directory resource.
		RT_FONT = 8							# Font resource.
		RT_ACCELERATOR = 9					# Accelerator table.
		RT_RCDATA = 10						# Application-defined resource (raw data.)
		RT_MESSAGETABLE = 11				# Message-table entry.
		RT_VERSION = 16						# Version resource.
		RT_DLGINCLUDE = 17					# Allows a resource editing tool to associate a string with an .rc file.
		RT_PLUGPLAY = 19					# Plug and Play resource.
		RT_VXD = 20							# VXD.
		RT_ANICURSOR = 21					# Animated cursor.
		RT_ANIICON = 22						# Animated icon.
		RT_HTML = 23						# HTML resource.
		RT_MANIFEST = 24					# Side-by-Side Assembly Manifest.

		RT_GROUP_CURSOR = RT_CURSOR + 11	# Hardware-independent cursor resource.
		RT_GROUP_ICON = RT_ICON + 11		# Hardware-independent icon resource.
		'''
		for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
			if resource_type.name is not None:
				name = "%s" % resource_type.name
			else:
				name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
			if name == None:
				name = "%d" % resource_type.struct.Id

			if hasattr(resource_type, 'directory'):
				i = 0
				for resource_id in resource_type.directory.entries:
					if len(resource_type.directory.entries) > 1:
						i = i+1
						newname = name+'_'+str(i)
					else:
						newname = name

					for resource_lang in resource_id.directory.entries:
						data_byte = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)[:50]
						is_pe = False
						if magic_check(data_byte)[:8]:
							is_pe = True
						lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
						sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)

						res_array.append({
							"name": newname,
							"data": str(data_byte),
							"executable": is_pe,
							"offset": resource_lang.data.struct.OffsetToData,
							"size": resource_lang.data.struct.Size, 
							"language": lang, 
							"sublanguage": sublang
							})
	except:
		pass

	return res_array

def magic_check(data):
	return re.findall(r'4d5a90', str(binascii.b2a_hex(data)))


import M2Crypto
def get_sign(pe):
	result = {}
	
	cert_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
	cert_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

	if cert_address != 0 and cert_size !=0:
		signature = pe.write()[cert_address+8:]
		details = {}

		bio = M2Crypto.BIO.MemoryBuffer(bytes(signature))
		if bio:
			pkcs7_obj = M2Crypto.m2.pkcs7_read_bio_der(bio.bio_ptr())
			if pkcs7_obj:
				p7 = M2Crypto.SMIME.PKCS7(pkcs7_obj)
				for cert in p7.get0_signers(M2Crypto.X509.X509_Stack()) or []:
					subject = cert.get_subject()

					try:
						serial_number = "%032x" % cert.get_serial_number()
					except:
						serial_number = ''
					try:
						common_name = subject.CN
					except:
						common_name = ''
					try:
						country = subject.C
					except:
						country = ''
					try:
						locality = subject.L
					except:
						locality = ''
					try:
						organization = subject.O
					except:
						organization = ''
					try:
						email = subject.Email
					except:
						email = ''
					try:
						valid_from = cert.get_not_before()
					except:
						valid_from = ''
					try:
						valid_to = cert.get_not_after()
					except:
						valid_to = ''
					details.update({
						"serial_number": str(serial_number),
						"common_name": str(common_name),
						"country": str(country),
						"locality": str(locality),
						"organization": str(organization),
						"email": str(email),
						"valid_from": str(valid_from),
						"valid_to": str(valid_to),
						"hash": {
							"sha1": "%040x" % int(cert.get_fingerprint("sha1"), 16),
							"md5": "%032x" % int(cert.get_fingerprint("md5"), 16),
							"sha256": "%064x" % int(cert.get_fingerprint("sha256"), 16)
							}
					})
	
		result.update({
			"virtual_address": cert_address, 
			"block_size": cert_size, 
			"details": details
			})

	return result

def get(pe):
	result = {}
	# The directory of imported symbols
	try:
		result.update({"import": get_import(pe)}) # dict
	except:
		result.update({"import": {}})

	# The directory of exported symbols; mostly used for DLLs.
	try: 
		result.update({"export": get_export(pe)}) # list
	except:
		result.update({"export": []})
	# Debug directory - contents is compiler dependent.
	try:
		result.update({"debug": get_debug(pe)}) # dict
	except:
		result.update({"debug": {}})
	# Thread local storage directory - structure unknown; contains variables that are declared
	try:
		result.update({"tls": get_tls(pe)}) # dict
	except:
		result.update({"tls": {}})
	# The resources, such as dialog boxes, menus, icons and so on, are stored in the data directory
	try:
		result.update({"resources": get_resources(pe)}) # list
	except:
		result.update({"resources": []})
	# PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
	try:
		result.update({"relocations": get_relocations(pe)}) # dict
	except:
		result.update({"relocations": {}})
	# Certificate
	try:
		result.update({"sign": get_sign(pe)}) # dict
	except:
		result.update({"sign": {}})
	
	return result
