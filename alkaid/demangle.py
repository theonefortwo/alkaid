# Basic metrowerks demangler. Known bugs, shouldn't be used in any sort of 'production' case

class DemangleStateException(Exception):
	pass

class Parameter:
	def __init__(self, pointer=None, second_pointer=None, classes=None, constant=None, reference=None):
		self.pointer = pointer if pointer is not None else False
		self.second_pointer = second_pointer if second_pointer is not None else False
		self.classes = classes if classes is not None else []
		self.constant = constant if constant is not None else False
		self.reference = reference if reference is not None else False
		return

	def __str__(self):
		ptr = '*' if self.pointer else ''
		sptr = '*' if self.second_pointer else ''
		cst = ' const' if self.constant else ''
		ref = '&' if self.reference else ''
		return '::'.join(self.classes)+ptr+sptr+cst+ref

class DemangledFunction:
	def __init__(self, function_name, classes, params, constant):
		self.function_name = function_name
		self.classes = classes
		self.params = params
		self.constant = constant

def demangle(mangled_name):
	omangled_name = mangled_name
	function_name = mangled_name.split('__')[0]
	if function_name == '':
		return DemangledFunction(mangled_name, [], [], False)
	mangled_name = '__'.join(mangled_name.split('__')[1:])
	state = 'initial_state'
	constant = False
	unsigned = False
	signed = False
	length = ''
	classes = []
	class_count = 0
	class_name = ''
	params = []
	current_parameter = Parameter()
	for char in mangled_name:
		if state == 'initial_state':
			if char in '0123456789':
				class_count = 1
				length += char
				state = 'class_len'
			elif char == '_':
				function_name += '_'
			elif char == 'Q':
				state = 'class_count'
			elif char == 'F':
				state = 'param_begin'
			else:
				raise DemangleStateException(f"initial_state: Unknown char {char} - {omangled_name}")
		elif state == 'class_count':
			class_count = int(char)
			state = 'class_len'
			length = ''
		elif state == 'class_len':
			if char in '0123456789':
				length += char
			else:
				class_name += char
				state = 'class_name'
				length = int(length)-1
		elif state == 'class_name':
			class_name += char
			length -= 1
			if length == 0:
				classes.append(class_name)
				class_count -= 1
				if class_count == 0:
					state = 'class_finish'
				else:
					state = 'class_len'
					class_name = ''
					length = ''
		elif state == 'class_finish':
			if char == 'F':
				state = 'param_begin'
			elif char == 'C':
				constant = True
			else:
				raise DemangleStateException(f"class_finish: unknown char {char} - {omangled_name}")
		elif state == 'param_begin':
			unsigned = False
			if char == 'v':
				params.append(Parameter(classes=['void']))
			elif char == 'i':
				params.append(Parameter(classes=['int']))
			elif char == 'U':
				unsigned = True
				state = 'param_info'
			elif char == 'S':
				signed = True
				state = 'param_info'
			elif char == 'f':
				params.append(Parameter(classes=['f32']))
			elif char == 'b':
				params.append(Parameter(classes=['bool']))
			elif char == 'c':
				params.append(Parameter(classes=['char']))
			elif char == 'e':
				params.append(Parameter(classes=['...']))
			elif char == 'P':
				current_parameter = Parameter(pointer=True)
				state = 'param_info'
			elif char == 'R':
				current_parameter = Parameter(reference=True)
				state = 'param_info'
			elif char in '1234567890':
				class_count = 1
				length = char
				state = 'param_class_len'
			elif char == 'Q':
				state = 'param_class_count'
				length = ''
			#elif char == 'l':
			#	print(f"warn: weird param_begin char 'l' appeared in {omangled_name}")
			else:
				raise DemangleStateException(f"param_begin: unknown char {char} - {omangled_name}")
		elif state == 'param_info':
			if char == 'Q':
				state = 'param_class_count'
				length = ''
			elif char == 'C':
				current_parameter.constant = True
			elif char == 'P':
				if current_parameter.pointer:
					current_parameter.second_pointer = True
				else:
					current_parameter.pointer = True
			elif char == 'i':
				current_parameter.classes = ['int']
				params.append(current_parameter)
				current_parameter = Parameter()
				state = 'param_begin'
			elif char == 'v':
				current_parameter.classes = ['void']
				params.append(current_parameter)
				current_parameter = Parameter()
				state = 'param_begin'
			elif char == 'c':
				if signed:
					current_parameter.classes = ['s8']
					params.append(current_parameter)
					current_parameter = Parameter()
					state = 'param_begin'
				else:
					current_parameter.classes = ['char']
					params.append(current_parameter)
					current_parameter = Parameter()
					state = 'param_begin'
			elif char == 'x':
				if unsigned:
					current_parameter.classes = ['u64']
					params.append(current_parameter)
					current_parameter = Parameter()
					state = 'param_begin'
				else:
					raise DemangleStateException(f"param_info: non-unsigned x. idk what this is. - {omangled_name}")
			elif char == 'U':
				unsigned = True
			elif char == 'f':
				current_parameter.classes = ['f32']
				params.append(current_parameter)
				current_parameter = Parameter()
				state = 'param_begin'
			elif char == 'b':
				current_parameter.classes = ['bool']
				params.append(current_parameter)
				current_parameter = Parameter()
				state = 'param_begin'
			elif char == 'l':
				if unsigned:
					current_parameter.classes = ['u32']
					params.append(current_parameter)
					current_parameter = Parameter()
					state = 'param_begin'
				else:
					raise DemangleStateException(f"param_info: non-unsigned long. idk what this is. - {omangled_name}")
			elif char == 's':
				if unsigned:
					current_parameter.classes = ['u16']
					params.append(current_parameter)
					current_parameter = Parameter()
					state = 'param_begin'
				else:
					raise DemangleStateException(f"param_info: non-unsigned short. idk what this is. - {omangled_name}")
			elif char in '1234567890':
				class_count = 1
				length = char
				state = 'param_class_len'
			else:
				raise DemangleStateException(f"param_info: unknown char {char} - {omangled_name}")
		elif state == 'param_class_count':
			class_count = int(char)
			state = 'param_class_len'
			length = ''
		elif state == 'param_class_len':
			class_name = ''
			if char in '0123456789':
				length += char
			else:
				class_name += char
				state = 'param_class_name'
				length = int(length)-1
		elif state == 'param_class_name':
			class_name += char
			length -= 1
			if length == 0:
				current_parameter.classes.append(class_name)
				class_count -= 1
				if class_count == 0:
					params.append(current_parameter)
					current_parameter = Parameter()
					state = 'param_begin'
				else:
					state = 'param_class_len'
					class_name = ''
					length = ''
	return DemangledFunction(function_name, classes, params, constant)

if __name__ == '__main__':
	while True:
		mangled_name = input()
		function_name, classes, params, constant = demangle(mangled_name)
		params = [str(param) for param in params]
		cst = ' const' if constant else ''
		demangled_human = '::'.join(classes)+'::'+function_name+'('+', '.join(params)+')'+cst
		print(demangled_human)
