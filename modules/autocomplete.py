#!/usr/bin/env python
# -*- coding: utf-8 -*-

# https://stackoverflow.com/questions/7821661/how-to-code-autocompletion-in-python

import readline

class MyCompleter(object):  # Custom completer

	def __init__(self, cmd_list):
		self.cmd_list = sorted(cmd_list)

	def complete(self, text, state):
		if state == 0:  # on first trigger, build possible matches
			if text:  # cache matches (entries that start with entered text)
				self.matches = [s for s in self.cmd_list 
									if s and s.startswith(text)]
			else:  # no text entered, all matches possible
				self.matches = self.cmd_list[:]

		# return match indexed by state
		try: 
			return self.matches[state]
		except IndexError:
			return None


def get_result(cmd_list, prompt_text):
	completer = MyCompleter(cmd_list)
	readline.set_completer(completer.complete)
	readline.set_completer_delims(' \t\n;')
	readline.parse_and_bind('tab: complete')

	for cmd in cmd_list:
		readline.add_history(cmd)

	raw = input(prompt_text+' ')

	return raw