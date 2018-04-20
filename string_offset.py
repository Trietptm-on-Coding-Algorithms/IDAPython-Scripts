#encoding: utf-8
import idautils
import idaapi

min = MinEA()
max = MaxEA()

for func in idautils.Functions():
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_LIB & flags & FUNC_THUNK:
		continue 
	dism_addr = list(idautils.FuncItems(func))
	for curr_addr in dism_addr:
		# o_imm = 5
		if idc.GetOpType(curr_addr, 0) == 5 and \
		   (min < idc.GetOperandValue(curr_addr, 0) < max):
			idc.OpOff(curr_addr, 0, 0)
		if idc.GetOpType(curr_addr, 0) == 5 and \
		   (min <　idc.GetOperandValue(curr_addr, 1) < max):
			idc.OpOff(curr_addr, 1, 0)