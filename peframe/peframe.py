#!/usr/bin/env python

# ----------------------------------------------------------------------
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

import os
import sys
import time
import datetime
import json
import argparse

from modules import pefile, peutils, pecore, stdoutput
from . import __version__, __summary__


def is_pe(filename):
    try:
        return pefile.PE(filename)
    except:
        msg = "%r is not a valid PE file" % filename
        raise argparse.ArgumentTypeError(msg)


def autoanalysis(pe, filename, json=False):
    if json:
        print pecore.get_info(pe, filename), \
            pecore.get_cert(pe), \
            pecore.get_packer(pe), \
            pecore.get_antidbg(pe), \
            pecore.get_antivm(filename), \
            pecore.get_xor(filename), \
            pecore.get_apialert(pe), \
            pecore.get_secalert(pe), \
            pecore.get_fileurl(filename), \
            pecore.get_meta(pe)

    else:
        stdoutput.show_auto(
            pecore.get_info(pe, filename),
            pecore.get_cert(pe),
            pecore.get_packer(pe),
            pecore.get_antidbg(pe),
            pecore.get_antivm(filename),
            pecore.get_xor(filename),
            pecore.get_apialert(pe),
            pecore.get_secalert(pe),
            pecore.get_fileurl(filename),
            pecore.get_meta(pe))


def main():

    parser = argparse.ArgumentParser(
        prog="peframe", usage="%(prog)s [options] malware.exe",
        description=__summary__)
    parser.add_argument("malware")
    parser.add_argument("-v", "--version", help="Version",
                        action="version", version="%(prog)s " + __version__)
    parser.add_argument(
        "--json", help="Output in json", action="store_true")
    parser.add_argument(
        "--imports", help="Imported DLL and functions", action="store_true")
    parser.add_argument(
        "--exports", help="Exported functions", action="store_true")
    parser.add_argument(
        "--dir-import", help="Import directory", action="store_true")
    parser.add_argument(
        "--dir-export", help="Export directory", action="store_true")
    parser.add_argument(
        "--dir-resource", help="Resource directory", action="store_true")
    parser.add_argument(
        "--dir-debug", help="Debug directory", action="store_true")
    parser.add_argument(
        "--dir-tls", help="TLS directory", action="store_true")
    parser.add_argument(
        "--strings", help="Get all strings", action="store_true")
    parser.add_argument(
        "--sections", help="Sections information", action="store_true")
    parser.add_argument(
        "--dump", help="Dump all information", action="store_true")

    args = parser.parse_args()

    filename = args.malware
    pe = is_pe(filename)

    # Auto Analysis
    if len(sys.argv) == 2:
        autoanalysis(pe, filename)

    if args.json:
        autoanalysis(pe, filename, json=True)

    if args.imports:
        stdoutput.show_import(pe)

    if args.exports:
        stdoutput.show_export(pe)

    if args.dir_import:
        stdoutput.show_directory(pe, "import")

    if args.dir_export:
        stdoutput.show_directory(pe, "export")

    if args.dir_resource:
        stdoutput.show_directory(pe, "resource")

    if args.dir_debug:
        stdoutput.show_directory(pe, "debug")

    if args.dir_tls:
        stdoutput.show_directory(pe, "tls")

    if args.strings:
        print pecore.get_strings(filename)

    if args.sections:
        print pecore.get_sections(pe)

    if args.dump:
        print pecore.get_dump(pe)

    return 0


if __name__ == '__main__':
    sys.exit(main())
