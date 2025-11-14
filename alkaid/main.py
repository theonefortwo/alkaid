import argparse
import os

from .dolfile import DOLFile
from .symbols import Symbols
from .fingerprint import generate_print, instruction_count
from .demangle import demangle, DemangleStateException

def alkaid_proc(path_to_dol, path_to_symbols, target_name=None):
	f = open(path_to_dol, 'rb')
	dolfile = DOLFile(f)
	f.close()
	f = open(path_to_symbols, 'r')
	symbols = Symbols(f)
	f.close()
	function_names = []
	function_prints = []
	for function_name, address, size in symbols.functions():
		try:
			demangled = demangle(function_name)
			function_name = '::'.join(demangled.classes)+'::'+demangled.function_name
		except DemangleStateException:
			pass
		function = dolfile.read_address(address, size)
		function_print = generate_print(function)
		function_names.append(function_name)
		function_prints.append(function_print)
	for i in range(len(function_names)):
		function_name = function_names[i]
		if target_name is not None and target_name not in function_name:
			continue
		function_print = function_prints[i]
		for j in range(len(function_names)):
			if i == j:
				continue
			new_print = function_prints[j]
			new_name = function_names[j]
			npic = instruction_count(new_print)
			if npic>16 and new_print[4:-4] in function_print and new_print != function_print:
				print(f"[confidence:{npic}] {new_name} is likely inlined in {function_name}")

def main():
	parser = argparse.ArgumentParser(
		description='Inline function finder',
		formatter_class=argparse.RawTextHelpFormatter
	)
	parser.add_argument(
		'path_to_dol',
		type=str,
		help='Path to the \'main.dol\' file.'
	)
	parser.add_argument(
		'path_to_symbols',
		type=str,
		help='Path to the \'symbols.txt\' file.'
	)
	parser.add_argument(
		'--target-name',
		type=str,
		default=None,
		help='The target function name to search for.'
	)
	args = parser.parse_args()
	alkaid_proc(args.path_to_dol, args.path_to_symbols, target_name=args.target_name)
