#!/usr/bin/env python
# -*- coding: utf-8 -*-

# by Gianni 'guelfoweb' Amato

import os
import re
import sys
import json
import magic
import pefile
import hashlib
from datetime import datetime

portable = False
for path in sys.path:
	if os.sep+'peframe'+os.sep+'peframe' in path:
		portable = True
if portable:
	from modules import directories
	from modules import features
	from modules import apialert
	from modules import yara_check
	from modules import meta
	from modules import virustotal
	from modules import sections
	from modules import fileurl
	from modules import macro
else:
	from peframe.modules import directories
	from peframe.modules import features
	from peframe.modules import apialert
	from peframe.modules import yara_check
	from peframe.modules import meta
	from peframe.modules import virustotal
	from peframe.modules import sections
	from peframe.modules import fileurl
	from peframe.modules import macro



def version():
	# 버전 확인을 위한 함수
	# command : peframe -v
	# return "6.0.3", type : String
	return "6.0.3"

def get_datetime_now():
	# 현재 시간을 확인하기 위한 함수
	# datetime.now()를 사용해 분석에 걸린 시간을 계산
	# return datetiem.now(), type : String, form : YYYY-MM-DD hh:mm:ss.xxxxxx
	return datetime.now()

def isfile(filename):
	# 특정 디렉토리 or 파일이 존재하는지 확인하는 함수
	# 매개변수인 filename에 들어가 있는 path값을 통해 os.path.isfile()함수를 통해 존재를 확인.
	# return True / False, 존재할 경우 True 없을경우 False
	if os.path.isfile(filename):
		return True
	return False

def ispe(filename):
	# re : regex 모듈은 정규표현식을 사용할 수 있도록 기능을 제공하는 내장 모듈
	# re.match() : 문자열의 처음부터 시작해 작성한 패턴(PE슛자... or MS-DOS...)이 존재하는지 확인
	# return True / False, PE파일일경우 True 아닐경우 False
	if re.match(r'^PE[0-9]{2}|^MS-DOS', filetype(filename)):
		return True
	return False

def filetype(filename):
	# magic : 유닉스에서 파일의 타입을 알려주는 file 명령어 모듈
	# magic.frome_file : 파일의 타입을 반환하는 함수
	# return file_type, type String, ex) "PE32 excutable (GUI) INtel 80386, for MS Windows"
	return magic.from_file(filename)

def filesize(filename):
	# os.path.getsize() : 파일의 사이즈를 바이트단위로 반환
	# return filesize, type : Integer, ex)  1 == 1 byte
	return os.path.getsize(filename)

def get_imphash(filename):
	# pefile : pefile에 대한 분석 기능을 제공하는 모듈
	# pefule.PE() : pefile 분석
	# imhash : import hash라고 불리며, PE구조를 가진 대상에서만 사용 가능, 실행 파일 내에서 특정 순서를 가지는 라이브러리와 API의 이름을 기준(IAT : Import Address Table)으로 해쉬값을 생성
	# return imhash, type = hash value
	pe = pefile.PE(filename)
	return pe.get_imphash()

def gethash(filename):
	# 파일의 해쉬값을 반환하는 함수
	# file을 처음부터 8192개의 문자까지 읽어 hash
	# 지원 형식 md5, sha1, sha256
	# return hashinfo, type = json, ex) 함수 내의 hashinfo.update({"md5"....구문 확인

	hashinfo = {}

	fh = open(filename, 'rb')
	m = hashlib.md5()
	s = hashlib.sha1()
	s256 = hashlib.sha256()
	
	while True:
		data = fh.read(8192)
		if not data:
			break

		m.update(data)
		s.update(data)
		s256.update(data)

	hashinfo.update({"md5": m.hexdigest(), "sha1": s.hexdigest(), "sha256": s256.hexdigest()})

	return hashinfo

def path_to_file(filename, folder):
	_ROOT = os.path.abspath(os.path.dirname(__file__))
	return os.path.join(_ROOT, folder, filename)

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

def analyze(filename):
	if not isfile(filename):
		exit("File not found")

	dt_start = get_datetime_now()

	fileinfo = {
		"version": version(),
		"filename": filename, 
		"filetype": filetype(filename),
		"filesize": filesize(filename),
		"hashes": gethash(filename),
		"virustotal": virustotal.get_result(
			load_config(
				path_to_file('config-peframe.json', 'config'))['virustotal'], 
			gethash(filename)['md5']),
		"strings": fileurl.get_result(filename, load_config(path_to_file('stringsmatch.json', 'signatures'))),
		}


	peinfo = {}
	docinfo = {}

	fileinfo.update({"docinfo": docinfo})
	fileinfo.update({"peinfo": peinfo})

	if ispe(filename):
		pe = pefile.PE(filename)
		peinfo.update({
			"imphash": pe.get_imphash(),
			"timestamp": datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
			"dll": pe.FILE_HEADER.IMAGE_FILE_DLL,
			"imagebase": pe.OPTIONAL_HEADER.ImageBase,
			"entrypoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
			"behavior": yara_check.yara_match_from_file(path_to_file('antidebug_antivm.yar', 'signatures/yara_plugins/pe'), filename),
			"breakpoint": apialert.get_result(pe, load_config(path_to_file('stringsmatch.json', 'signatures'))['breakpoint']),
			"directories": directories.get(pe),
			"features": features.get_result(pe, filename),
			"sections": sections.get_result(pe),
			"metadata": meta.get(pe)
			})
		fileinfo.update({"peinfo": peinfo})
		fileinfo.update({"yara_plugins": yara_check.yara_match_from_folder(path_to_file('pe', 'signatures/yara_plugins'), filename, ['antidebug_antivm.yar'])})
	else:
		fileinfo.update({"docinfo": macro.get_result(filename)})
		fileinfo.update({"yara_plugins": yara_check.yara_match_from_folder(path_to_file('doc', 'signatures/yara_plugins'), filename)})

	dt_end = get_datetime_now()

	fileinfo.update({"time": str(dt_end - dt_start)})

	return fileinfo
