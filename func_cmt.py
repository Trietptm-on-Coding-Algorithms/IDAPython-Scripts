#encoding: utf-8
import idautils

def rename_wrapper(name, func_addr):
	if idc.MakeNameEx(func_addr, name, SN_NOWARN):
		print "Function at 0x%x renamed  %s" % (func_addr, idc.GetFunctionName(func))
	else:
		print "Renamed at 0x%x failed. Function %s is being used." % (func_addr, name)
	return 
def check_for_wrapper(func):
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_LIB or flags & FUNC_THUNK:
		return 
	dism_addr = list(idautils.FuncItems(func))
	func_length = len(dism_addr)
	# if over 32 lines of instruction return 
	if func_length > 0x20:
		return 
	func_call = 0
	instr_cmp = 0
	op = None
	op_addr = None
	op_type = None

	for ea in dism_addr:
		m = idc.GetMnem(ea)
		if m == 'call' or m == 'jmp':
			if m == 'jmp':
				temp = idc.GetOperandValue(ea, 0)
				#ignore jump conditions within the function boundaries
				if temp in dism_addr:
					continue
			func_call += 1
			# wrappers should not contain multiple function calls
			if func_call == 2:
				return
			op_addr = idc.GetOperandValue(ea, 0)
			op_type = idc.GetOpType(ea, 0)
		elif m == 'cmp' or m == 'test':
			# wrappers should not contain multiple function calls
			instr_cmp += 1
			if instr_cmp == 3:
				return
		else:
			continue
	# all instructions in the function have been analyzed
	if op_addr == None:
		return 
	name = idc.Name(op_addr)
	# skip mangled function names
	if "[" in name or "$" in name or "?" in name or "@" in name or name == "";
		return 
	name = "w_" + name
	if op_type == 7:
		if idc.GetFunctionFlags(op_addr) & FUNC_THUNK:
			rename_wrapper(name, func)
			return 
	if op_type == 2 or op_type == 6:
		rename_wrapper(name, func)
		return 
for func in idautils.Functions():
	check_for_wrapper(func)	