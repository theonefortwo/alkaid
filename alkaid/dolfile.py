import struct

class DOLFile:
	def __init__(self, f):
		self.load_from_file(f)
		return

	def load_from_file(self, file_object):
		file_object.seek(0)
		header = file_object.read(0xFF)
		self.text_offsets = struct.unpack('>7I', header[0x00:0x1C])
		self.data_offsets = struct.unpack('>11I', header[0x1C:0x48])
		self.text_address = struct.unpack('>7I', header[0x48:0x64])
		self.data_address = struct.unpack('>11I', header[0x64:0x90])
		self.text_secsize = struct.unpack('>7I', header[0x90:0xAC])
		self.data_secsize = struct.unpack('>11I', header[0xAC:0xD8])
		self.bss_address = struct.unpack('>I', header[0xD8:0xDC])
		self.bss_size = struct.unpack('>I', header[0xDC:0xE0])
		self.entry_point = struct.unpack('>I', header[0xE0:0xE4])
		self.text_segments = []
		self.data_segments = []
		for i in range(7):
			offset = self.text_offsets[i]
			size = self.text_secsize[i]
			file_object.seek(offset)
			self.text_segments.append(file_object.read(size))
		for i in range(11):
			offset = self.data_offsets[i]
			size = self.data_secsize[i]
			file_object.seek(offset)
			self.data_segments.append(file_object.read(size))

	def read_address(self, address, size=1):
		for i in range(8):
			min_address = self.text_address[i]
			max_address = min_address + self.text_secsize[i]
			if min_address <= address and address+size <= max_address:
				return self.text_segments[i][address-min_address:(address+size)-min_address]
		for i in range(12):
			min_address = self.data_address[i]
			max_address = min_address + self.data_secsize[i]
			if min_address <= address and address+size <= max_address:
				return self.data_segments[i][address-min_address:(address+size)-min_address]
