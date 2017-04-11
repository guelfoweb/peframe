#!/usr/bin/env python

# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PEframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PEframe. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

# Feb 4 2015: Edited by geurdrik. Returned objects that are useable by other things...
import json

import pefile
import peutils

import info
import cert
import peid
import loadfile
import apiantidbg
import xor
import antivm
import apialert
import secalert
import fileurl
import meta

import funcimport
import funcexport
import sections
import strings
import dump
import directory

global filename
global pe

def get_info(pe, filename, obj = False):
    show_info = json.loads(info.get(pe, filename))
    if not obj:
        return json.dumps({"Short Info": show_info}, indent=4, separators=(',', ': '))
    return show_info

def get_cert(pe, obj = False):
    show_cert = json.loads(cert.get(pe))
    if not obj:
        return json.dumps({"Digital Signature": show_cert}, indent=4, separators=(',', ': '))
    return show_cert

def get_packer(pe, obj = False):
    show_packer = peid.get(pe)
    if not obj:
        return json.dumps({"Packer": show_packer}, indent=4, separators=(',', ': '))
    return show_packer

def get_antidbg(pe, obj = False):
    show_antidbg = apiantidbg.get(pe)
    if not obj:
        return json.dumps({"Anti Debug": show_antidbg}, indent=4, separators=(',', ': '))
    return show_antidbg

def get_xor(pe, obj = False):
    show_xor = xor.get(pe)
    if not obj:
        return json.dumps({"Xor": show_xor[0], "Offset": show_xor[1]}, indent=4, separators=(',', ': '))
    return show_xor

def get_antivm(filename, obj = False):
    show_antivm = antivm.get(filename)
    if not obj:
        return json.dumps({"Anti VM": show_antivm}, indent=4, separators=(',', ': '))
    return show_antivm

def get_apialert(pe, obj = False):
    show_apialert = apialert.get(pe)
    if not obj:
        return json.dumps({"Suspicious API": show_apialert}, indent=4, separators=(',', ': '))
    return show_apialert

def get_secalert(pe, obj = False):
    show_secalert = secalert.get(pe)
    if not obj:
        return json.dumps({"Suspicious Sections": show_secalert}, indent=4, separators=(',', ': '))
    return show_secalert

def get_fileurl(filename, obj = False):
    show_fileurl = fileurl.get(filename)
    if not obj:
        return json.dumps({"File Name": show_fileurl[0], "Url": show_fileurl[1]}, indent=4, separators=(',', ': '))
    return show_fileurl

def get_meta(pe, obj = False):
    show_meta = meta.get(pe)
    if not obj:
        return json.dumps({"Meta Data": show_meta}, indent=4, separators=(',', ': '))
    return show_meta

# Options

def get_import(pe):
    show_import = funcimport.get(pe)
    return json.dumps({"Imported Functions": show_import}, indent=4, separators=(',', ': '))

def get_export(pe):
    show_export = funcexport.get(pe)
    return json.dumps({"Exported Functions": show_export}, indent=4, separators=(',', ': '))

def get_sections(pe):
    show_sections = sections.get(pe)
    return json.dumps({"Sections": show_sections}, indent=4, separators=(',', ': '))

def get_strings(filename):
    show_strings = strings.get(filename)
    return show_strings

def get_dump(pe):
    return dump.get(pe)

def get_dir(pe, d):
    if d == "import":
        return directory.get_import(pe)
    if d == "export":
        return directory.get_export(pe)
    if d == "resource":
        return directory.get_resource(pe)
    if d == "debug":
        return directory.get_debug(pe)
    if d == "tls":
        return directory.get_tls(pe)
