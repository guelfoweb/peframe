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

import os
import sqlite3 as lite

PEFRAMEDB	= "db"  + os.sep +  "peframe.db"

def dbmanage(name,size,time,dll,sect,md5, \
			sha1,imph,packer,antidbg,antivm,directory,pefver,date, \
			au_show_pack,au_show_adbg,au_show_avm,au_show_api, \
			au_show_sec,au_show_furl,au_show_meta):
						
	# connect to db
	con = lite.connect(PEFRAMEDB)
	con.text_factory = str
	cur = con.cursor()
	cur.execute("SELECT * FROM short WHERE md5='" + md5 + "'")
	row = cur.fetchall()

	#TODO:
	#
	# ver = row[0][1] # old version number
	#
	# if row and ver > pefver:
	#	delete row
	#	wirte new report analysis
	#
	
	# verify if md5 exist
	if not row:
		# write short information in db
		print "\nWait please... storing info into the db"
		cur.execute('''
		INSERT INTO short (filename, filesize, timestamp, dll, sections, \
							md5, sha1, imphash, packer, antidbg, antivm, \
							directory, pefversion, datetime) \
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
					''', \
							(name,size,time,dll,sect, \
							md5, sha1,imph,packer,antidbg,antivm, \
							directory,pefver,date))
		con.commit()

		# return the id for the last row that cur inserted
		idrif = cur.lastrowid

		# collect SHOW data to store in db	
	
		# packer
		if au_show_pack:
			for i in range(0, len(au_show_pack)):
				cur.execute('''INSERT INTO show_packer (id, name) VALUES (?, ?)''', (idrif, au_show_pack[i]))
				con.commit()
			
		# anti debug
		if au_show_adbg:
			for i in range(0, len(au_show_adbg)):
				cur.execute('''INSERT INTO show_antidbg (id, name) VALUES (?, ?)''', (idrif, au_show_adbg[i]))
				con.commit()
			
		# anti virtual machine
		if au_show_avm:
			for i in range(0, len(au_show_avm)):
				cur.execute('''INSERT INTO show_antivm (id, name) VALUES (?, ?)''', (idrif, au_show_avm[i]))
				con.commit()
			
		# api suspicious
		if au_show_api:
			for i in range(0, len(au_show_api)):
				cur.execute('''INSERT INTO show_apisuspicious (id, name) VALUES (?, ?)''', (idrif, au_show_api[i]))
				con.commit()
			
		# sections suspicious
		if au_show_sec:
			for i in range(0, len(au_show_sec)):
				cur.execute('''INSERT INTO show_secsuspicious (id, name, md5, sha1) VALUES (?, ?, ?, ?)''', \
							(idrif, au_show_sec[i][0], au_show_sec[i][1], au_show_sec[i][2]))
				con.commit()

		# file and url
		if au_show_furl:
			if len(au_show_furl) == 2:
				if len(au_show_furl[0][0]) == 2:
					# file
					for i in range(0, len(au_show_furl[0])):
						cur.execute('''INSERT INTO show_file (id, file) VALUES (?, ?)''', (idrif, au_show_furl[0][i][1]))
						con.commit()
					# url
					for i in range(0,len(au_show_furl[1])):
						cur.execute('''INSERT INTO show_url (id, url) VALUES (?, ?)''', (idrif, au_show_furl[1][i][1]))
						con.commit()
			if len(au_show_furl) == 1:
				# file
				if len(au_show_furl[0][0]) == 2:
					cur.execute('''INSERT INTO show_file (id, file) VALUES (?, ?)''', (idrif, au_show_furl[0][1]))
					con.commit()
				# url
				if len(au_show_furl[0][0]) == 1:
					cur.execute('''INSERT INTO show_eurl (id, url) VALUES (?, ?)''', (idrif, au_show_furl[0][0]))
					con.commit()

		# meta data
		if au_show_meta:
			for i in range(0, len(au_show_meta)):
				cur.execute('''INSERT INTO show_meta (id, meta) VALUES (?, ?)''', (idrif, str(au_show_meta[i][0])+": "+str(au_show_meta[i][1])))
				con.commit()

		# close db connection
		con.close
		print "\nAdded to databse."
