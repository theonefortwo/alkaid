# symbols.txt parser

class Symbols:
	def __init__(self, f):
		self.syms = {}
		self.load_from_file(f)
		return

	def load_from_file(self, file_object):
		for line in file_object:
			if line.endswith('\n'):
				line = line[:-1]
			if '; // ' not in line:
				continue
			primary, xinfo = line.split('; // ')
			name, address = primary.split(' = ')
			address = int(address.split(':0x')[1], 16)
			info = {}
			for ik in xinfo.split(' '):
				if ':' in ik:
					info[ik.split(':')[0]] = ik.split(':')[1]
				else: # e.g. noreloc
					info[ik] = True
			if 'size' not in info:
				info['size'] = '0x0'
			if info['type'] not in self.syms:
				self.syms[info['type']] = []
			self.syms[info['type']].append([name, address, int(info['size'][2:], 16)])

	def functions(self):
		if 'function' not in self.syms:
			return []
		return self.syms['function']
