import struct

instruction_table = []

def num_to_byte(i):
	if i > 254:
		b = b"\xff"
		b += (i - 255).to_bytes(1, 'little')
	else:
		b = i.to_bytes(1, 'little')
	return b

class UnknownInstructionException(Exception):
	pass

def lookup_instruction(instruction):
		if type(instruction) == bytes:
			instruction = struct.unpack('>I', instruction)[0]
		primary_opcode = (instruction & 0b11111100000000000000000000000000) >> 26
		for i in range(len(instruction_table)):
			inst = instruction_table[i]
			primary_check, extended, extended_mask, extended_shift, extended_check, name = inst
			if primary_opcode == primary_check:
				if extended:
					extended_opcode = (instruction & extended_mask) >> extended_shift
					if extended_opcode == extended_check:
						return num_to_byte(i)
				else:
					return num_to_byte(i)
		raise UnknownInstructionException(f"Unknown instruction {hex(instruction)}")

def instruction_count(fingerprint):
	count = 0
	for char in fingerprint:
		if char == 0xFF:
			continue
		count += 1
	return count

def generate_print(function):
	fingerprint = b""
	for i in range(0, len(function), 4):
		instruction = function[i:i+4]
		fingerprint += lookup_instruction(instruction)
	return fingerprint

def add_instruction(primary_opcode, format, extended_opcode, mnemonic):
	if format == 'XO':
		# 0b10000000001
		# --
		fextop = (extended_opcode<<1)
		instruction_table.append([primary_opcode, True, 0b11111111111, 0, fextop, mnemonic])
		# o-
		fextop = (extended_opcode<<1)^0b10000000000
		instruction_table.append([primary_opcode, True, 0b11111111111, 0, fextop, mnemonic+'o'])
		# -.
		fextop = (extended_opcode<<1)^0b00000000001
		instruction_table.append([primary_opcode, True, 0b11111111111, 0, fextop, mnemonic+'.'])
		# o.
		fextop = (extended_opcode<<1)^0b10000000001
		instruction_table.append([primary_opcode, True, 0b11111111111, 0, fextop, mnemonic+'o.'])
	elif format == 'D' or format == 'I' or format == 'B':
		instruction_table.append([primary_opcode, False, 0, 0, 0, mnemonic])
	elif format == 'X' or format == 'XL' or format == 'XFX' or format == 'XFL':
		# 0b00000000001
		# -
		fextop = (extended_opcode<<1)
		instruction_table.append([primary_opcode, True, 0b11111111111, 0, fextop, mnemonic])
		# .
		fextop = (extended_opcode<<1)^0b0000000001
		instruction_table.append([primary_opcode, True, 0b11111111111, 0, fextop, mnemonic+'.'])
	elif format == 'DS':
		# 0b11
		fextop = extended_opcode
		instruction_table.append([primary_opcode, True, 0b11, 0, fextop, mnemonic])
	elif format == 'SC':
		# 0b1/
		for i in range(2):
			fextop = i
			instruction_table.append([primary_opcode, True, 0b10, 1, fextop, mnemonic+str(i)])
	elif format == 'A':
		# 0b000001
		# -
		fextop = (extended_opcode<<1)
		instruction_table.append([primary_opcode, True, 0b111111, 0, fextop, mnemonic])
		# .
		fextop = (extended_opcode<<1)^0b000001
		instruction_table.append([primary_opcode, True, 0b111111, 0, fextop, mnemonic+'.'])
	elif format == 'MDS':
		# 0b00001
		# -
		fextop = (extended_opcode<<1)
		instruction_table.append([primary_opcode, True, 0b11111, 0, fextop, mnemonic])
		# .
		fextop = (extended_opcode<<1)^0b00001
		instruction_table.append([primary_opcode, True, 0b11111, 0, fextop, mnemonic+'.'])
	elif format == 'MD':
		# 0b000xx
		fextop = extended_opcode
		instruction_table.append([primary_opcode, True, 0b11100, 2, fextop, mnemonic])
	elif format == 'M':
		# 0b1
		# -
		fextop = 0b0
		instruction_table.append([primary_opcode, True, 0b1, 0, fextop, mnemonic])
		# .
		fextop = 0b1
		instruction_table.append([primary_opcode, True, 0b1, 0, fextop, mnemonic+'.'])
	elif format == 'XS':
		# 0b000000000xx
		fextop = extended_opcode
		instruction_table.append([primary_opcode, True, 0b11111111100, 2, fextop, mnemonic])
	elif format == 'GEKKO1':
		# 0b000000x
		fextop = extended_opcode
		instruction_table.append([primary_opcode, True, 0b1111110, 1, fextop, mnemonic])
	else:
		print(f"unk format {format}")

add_instruction(31, 'XO', 266, 'add')
add_instruction(31, 'XO', 10, 'addc')
add_instruction(31, 'XO', 138, 'adde')
add_instruction(14, 'D', None, 'addi')
add_instruction(12, 'D', None, 'addic')
add_instruction(13, 'D', None, 'addic.')
add_instruction(15, 'D', None, 'addis')
add_instruction(31, 'XO', 234, 'addme')
add_instruction(31, 'XO', 202, 'addze')
add_instruction(31, 'X', 28, 'and')
add_instruction(31, 'X', 60, 'andc')
add_instruction(28, 'D', None, 'andi.')
add_instruction(29, 'D', None, 'andis.')
add_instruction(18, 'I', None, 'b')
add_instruction(16, 'B', None, 'bc')
add_instruction(19, 'XL', 528, 'bcctr')
add_instruction(19, 'XL', 16, 'bclr')
add_instruction(31, 'X', 0, 'cmp')
add_instruction(11, 'D', None, 'cmpi')
add_instruction(31, 'X', 32, 'cmpl')
add_instruction(10, 'D', None, 'cmpli')
add_instruction(31, 'X', 58, 'cntlzd')
add_instruction(31, 'X', 26, 'cntlzw')
add_instruction(19, 'XL', 257, 'crand')
add_instruction(19, 'XL', 129, 'crandc')
add_instruction(19, 'XL', 289, 'creqv')
add_instruction(19, 'XL', 225, 'crnand')
add_instruction(19, 'XL', 33, 'crnor')
add_instruction(19, 'XL', 449, 'cror')
add_instruction(19, 'XL', 417, 'crorc')
add_instruction(19, 'XL', 193, 'crxor')
add_instruction(31, 'X', 86, 'dcbf')
add_instruction(31, 'X', 470, 'dcbi')
add_instruction(31, 'X', 54, 'dcbst')
add_instruction(31, 'X', 278, 'dcbt')
add_instruction(31, 'X', 246, 'dcbtst')
add_instruction(31, 'X', 1014, 'dcbz')
add_instruction(31, 'XO', 489, 'divd')
add_instruction(31, 'XO', 457, 'divdu')
add_instruction(31, 'XO', 491, 'divw')
add_instruction(31, 'XO', 459, 'divwu')
add_instruction(31, 'X', 310, 'eciwx')
add_instruction(31, 'X', 438, 'ecowx')
add_instruction(31, 'X', 854, 'eieio')
add_instruction(31, 'X', 284, 'eqv')
add_instruction(31, 'X', 954, 'extsb')
add_instruction(31, 'XO', 922, 'extsh')
add_instruction(31, 'X', 986, 'extsw')
add_instruction(63, 'X', 264, 'fabs')
add_instruction(63, 'A', 21, 'fadd')
add_instruction(59, 'A', 21, 'fadds')
add_instruction(63, 'X', 846, 'fcfid')
add_instruction(63, 'X', 32, 'fcmpo')
add_instruction(63, 'XL', 0, 'fcmpu')
add_instruction(63, 'X', 814, 'fctid')
add_instruction(63, 'X', 815, 'fctidz')
add_instruction(63, 'X', 14, 'fctiw')
add_instruction(63, 'XL', 15, 'fctiwz')
add_instruction(63, 'A', 18, 'fdiv')
add_instruction(59, 'A', 18, 'fdivs')
add_instruction(63, 'A', 29, 'fmadd')
add_instruction(59, 'A', 29, 'fmadds')
add_instruction(63, 'X', 72, 'fmr')
add_instruction(63, 'A', 28, 'fmsub')
add_instruction(59, 'A', 28, 'fmsubs')
add_instruction(63, 'A', 25, 'fmul')
add_instruction(59, 'A', 25, 'fmuls')
add_instruction(63, 'X', 136, 'fnabs')
add_instruction(63, 'X', 40, 'fneg')
add_instruction(63, 'A', 31, 'fnmadd')
add_instruction(59, 'A', 31, 'fnmadds')
add_instruction(63, 'A', 30, 'fnmsub')
add_instruction(59, 'A', 30, 'fnmsubs')
add_instruction(59, 'A', 24, 'fres')
add_instruction(63, 'X', 12, 'frsp')
add_instruction(63, 'A', 26, 'frsqrte')
add_instruction(63, 'A', 23, 'fsel')
add_instruction(63, 'A', 20, 'fsub')
add_instruction(59, 'A', 20, 'fsubs')
add_instruction(31, 'X', 982, 'icbi')
add_instruction(19, 'X', 150, 'isync')
add_instruction(34, 'D', None, 'lbz')
add_instruction(35, 'D', None, 'lbzu')
add_instruction(31, 'X', 119, 'lbzux')
add_instruction(31, 'X', 87, 'lbzx')
add_instruction(58, 'DS', 0, 'ld')
add_instruction(31, 'X', 84, 'ldarx')
add_instruction(58, 'DS', 1, 'ldu')
add_instruction(31, 'X', 53, 'ldux')
add_instruction(31, 'X', 21, 'ldx')
add_instruction(50, 'D', None, 'lfd')
add_instruction(51, 'D', None, 'lfdu')
add_instruction(31, 'X', 631, 'lfdux')
add_instruction(31, 'X', 599, 'lfdx')
add_instruction(48, 'D', None, 'lfs')
add_instruction(49, 'D', None, 'lfsu')
add_instruction(31, 'X', 567, 'lfsux')
add_instruction(31, 'X', 535, 'lfsx')
add_instruction(42, 'D', None, 'lha')
add_instruction(43, 'D', None, 'lhau')
add_instruction(31, 'X', 375, 'lhaux')
add_instruction(31, 'X', 343, 'lhax')
add_instruction(31, 'X', 790, 'lhbrx')
add_instruction(40, 'D', None, 'lhz')
add_instruction(41, 'D', None, 'lhzu')
add_instruction(31, 'X', 331, 'lhzux')
add_instruction(31, 'X', 279, 'lhzx')
add_instruction(46, 'D', None, 'lmw')
add_instruction(31, 'X', 597, 'lswi')
add_instruction(31, 'X', 533, 'lswx')
add_instruction(58, 'DS', 2, 'lwa')
add_instruction(31, 'X', 20, 'lwarx')
add_instruction(31, 'X', 373, 'lwaux')
add_instruction(31, 'X', 341, 'lwax')
add_instruction(31, 'X', 534, 'lwbrx')
add_instruction(32, 'D', None, 'lwz')
add_instruction(33, 'D', None, 'lwzu')
add_instruction(31, 'X', 55, 'lwzux')
add_instruction(31, 'X', 23, 'lwzx')
add_instruction(19, 'XL', 0, 'mcrf')
add_instruction(63, 'X', 64, 'mcrfs')
add_instruction(31, 'X', 512, 'mcrxr')
add_instruction(31, 'X', 19, 'mfcr')
add_instruction(63, 'X', 583, 'mffs')
add_instruction(31, 'X', 83, 'mfmsr')
add_instruction(31, 'X', 339, 'mfspr')
add_instruction(31, 'X', 595, 'mfsr')
add_instruction(31, 'X', 659, 'mfsrin')
add_instruction(31, 'XFX', 144, 'mtcrf')
add_instruction(63, 'X', 70, 'mtfsb0')
add_instruction(63, 'X', 38, 'mtfsb1')
add_instruction(63, 'XFL', 711, 'mtfsf')
add_instruction(63, 'X', 134, 'mtfsfi')
add_instruction(31, 'X', 146, 'mtmsr')
add_instruction(31, 'X', 467, 'mtspr')
add_instruction(31, 'X', 210, 'mtsr')
add_instruction(31, 'X', 242, 'mtsrin')
add_instruction(31, 'XO', 73, 'mulhd')
add_instruction(31, 'XO', 9, 'mulhdu')
add_instruction(31, 'XO', 75, 'mulhw')
add_instruction(31, 'XO', 11, 'mulhwu')
add_instruction(31, 'XO', 233, 'mulld')
add_instruction(7, 'D', None, 'mulli')
add_instruction(31, 'XO', 235, 'mullw')
add_instruction(31, 'X', 476, 'nand')
add_instruction(31, 'XO', 104, 'neg')
add_instruction(31, 'X', 124, 'nor')
add_instruction(31, 'X', 444, 'or')
add_instruction(31, 'X', 412, 'orc')
add_instruction(24, 'D', None, 'ori')
add_instruction(25, 'D', None, 'oris')
add_instruction(19, 'X', 50, 'rfi')
add_instruction(30, 'MDS', 8, 'rldcl')
add_instruction(30, 'MDS', 9, 'rldcr')
add_instruction(30, 'MD', 2, 'rldic')
add_instruction(30, 'MD', 0, 'rldicl')
add_instruction(30, 'MD', 1, 'rldicr')
add_instruction(30, 'MD', 3, 'rldimi')
add_instruction(20, 'M', None, 'rlwimi')
add_instruction(21, 'M', None, 'rlwinm')
add_instruction(23, 'M', None, 'rlwnm')
add_instruction(17, 'SC', None, 'sc')
add_instruction(12, 'D', None, 'si')
add_instruction(13, 'D', None, 'si.')
add_instruction(31, 'X', 498, 'slbia')
add_instruction(31, 'X', 434, 'slbie')
add_instruction(31, 'X', 27, 'sld')
add_instruction(31, 'X', 24, 'slw')
add_instruction(31, 'X', 794, 'srad')
add_instruction(31, 'XS', 413, 'sradi')
add_instruction(31, 'X', 539, 'srd')
add_instruction(31, 'X', 792, 'sraw')
add_instruction(31, 'X', 824, 'srawi')
add_instruction(31, 'X', 536, 'srw')
add_instruction(38, 'D', None, 'stb')
add_instruction(39, 'D', None, 'stbu')
add_instruction(31, 'X', 247, 'stbux')
add_instruction(31, 'X', 215, 'stbx')
add_instruction(62, 'DS', 0, 'std')
add_instruction(31, 'X', 214, 'stdcx')
add_instruction(62, 'DS', 1, 'stdu')
add_instruction(31, 'X', 181, 'stdux')
add_instruction(31, 'X', 149, 'stdx')
add_instruction(54, 'D', None, 'stfd')
add_instruction(55, 'D', None, 'stfdu')
add_instruction(31, 'X', 759, 'stfdux')
add_instruction(31, 'X', 727, 'stfdx')
add_instruction(31, 'X', 983, 'stfiwx')
add_instruction(52, 'D', None, 'stfs')
add_instruction(53, 'D', None, 'stfsu')
add_instruction(31, 'X', 695, 'stfsux')
add_instruction(31, 'X', 663, 'stfsx')
add_instruction(44, 'D', None, 'sth')
add_instruction(31, 'X', 918, 'sthbrx')
add_instruction(45, 'D', None, 'sthu')
add_instruction(31, 'X', 439, 'sthux')
add_instruction(31, 'X', 407, 'sthx')
add_instruction(47, 'D', None, 'stmw')
add_instruction(31, 'X', 725, 'stswi')
add_instruction(31, 'X', 661, 'stswx')
add_instruction(36, 'D', None, 'stw')
add_instruction(31, 'X', 662, 'stwbrx')
add_instruction(31, 'X', 150, 'stwcx')
add_instruction(37, 'D', None, 'stwu')
add_instruction(31, 'X', 183, 'stwux')
add_instruction(31, 'X', 151, 'stwx')
add_instruction(31, 'XO', 40, 'subf')
add_instruction(31, 'XO', 8, 'subfc')
add_instruction(31, 'XO', 136, 'subfe')
add_instruction(8, 'D', None, 'subfic')
add_instruction(31, 'XO', 232, 'subfme')
add_instruction(31, 'XO', 200, 'subfze')
add_instruction(31, 'X', 598, 'sync')
add_instruction(31, 'X', 68, 'td')
add_instruction(2, 'D', None, 'tdi')
add_instruction(31, 'X', 306, 'tlbie')
add_instruction(31, 'X', 566, 'tlbsync')
add_instruction(31, 'X', 4, 'tw')
add_instruction(3, 'D', None, 'twi')
add_instruction(31, 'X', 316, 'xor')
add_instruction(26, 'D', None, 'xori')
add_instruction(27, 'D', None, 'xoris')
add_instruction(31, 'X', 371, 'mftb')
# Gekko
add_instruction(4, 'X', 0b0000000000, 'ps_cmpu0')
add_instruction(4, 'GEKKO1', 0b000110, 'psq_lx')
add_instruction(4, 'GEKKO1', 0b000111, 'psq_stx')
add_instruction(4, 'A', 0b01010, 'ps_sum0')
add_instruction(4, 'A', 0b01011, 'ps_sum1')
add_instruction(4, 'A', 0b01100, 'ps_muls0')
add_instruction(4, 'A', 0b01101, 'ps_muls1')
add_instruction(4, 'A', 0b01110, 'ps_madds0')
add_instruction(4, 'A', 0b01111, 'ps_madds1')
add_instruction(4, 'A', 0b10010, 'ps_div')
add_instruction(4, 'A', 0b10100, 'ps_sub')
add_instruction(4, 'A', 0b10101, 'ps_add')
add_instruction(4, 'A', 0b10111, 'ps_sel')
add_instruction(4, 'A', 0b11000, 'ps_res')
add_instruction(4, 'A', 0b11001, 'ps_mul')
add_instruction(4, 'A', 0b11010, 'ps_rsqrte')
add_instruction(4, 'A', 0b11100, 'ps_msub')
add_instruction(4, 'A', 0b11101, 'ps_madd')
add_instruction(4, 'A', 0b11110, 'ps_nmsub')
add_instruction(4, 'A', 0b11111, 'ps_nmadd')
add_instruction(4, 'X', 0b0000100000, 'ps_cmpo0')
add_instruction(4, 'GEKKO1', 0b100110, 'psq_lux')
add_instruction(4, 'GEKKO1', 0b100111, 'psq_stux')
add_instruction(4, 'X', 0b0000101000, 'ps_neg')
add_instruction(4, 'X', 0b0001000000, 'ps_cmpu1')
add_instruction(4, 'X', 0b0001001000, 'ps_mr')
add_instruction(4, 'X', 0b0001100000, 'ps_cmpo1')
add_instruction(4, 'X', 0b0010001000, 'ps_nabs')
add_instruction(4, 'X', 0b0100001000, 'ps_abs')
add_instruction(4, 'X', 0b1000010000, 'ps_merge00')
add_instruction(4, 'X', 0b1000110000, 'ps_merge01')
add_instruction(4, 'X', 0b1001010000, 'ps_merge10')
add_instruction(4, 'X', 0b1001110000, 'ps_merge11')
add_instruction(4, 'X', 0b1111110110, 'dcbz_l')
add_instruction(56, 'D', None, 'psq_l')
add_instruction(57, 'D', None, 'psq_lu')
add_instruction(60, 'D', None, 'psq_st')
add_instruction(61, 'D', None, 'psq_stu')
