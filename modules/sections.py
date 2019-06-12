#!/usr/bin/env python
# -*- coding: utf-8 -*-

# https://gist.github.com/rjzak/47c28bf3421241c03653f1619e0d8d92
def isSectionExecutable(section):
	characteristics = getattr(section, 'Characteristics')
	if characteristics & 0x00000020 > 0 or characteristics & 0x20000000 > 0:
		return True
	return False

def get_result(pe):
	array = []
	for section in pe.sections:
		try:
			section_name = str(section.Name, 'utf-8').encode('ascii', errors='ignore').strip().decode('ascii')
		except:
			section_name = str(section.Name, 'ISO-8859-1').encode('ascii', errors='ignore').strip().decode('ascii')

		section_name = section_name.replace('\u0000', '')

		if section_name == '':
			section_name = '.noname'

		array.append({
			"section_name": section_name,
			"executable": isSectionExecutable(section),
			"characteristics": section.Characteristics,
			"virtual_address": section.VirtualAddress,
			"virtual_size": section.Misc_VirtualSize,
			"size_of_raw_data": section.SizeOfRawData,
			"hash": {
				"md5": section.get_hash_md5(),
				"sha1": section.get_hash_sha1(),
				"sha256": section.get_hash_sha256(),
			},
			"entropy": section.get_entropy(),
			"data": str(section.get_data())[:50] #.rstrip(b'\x00'))
			})

	return {"count": pe.FILE_HEADER.NumberOfSections, "details": array}
