import idautils
import idaappi
displace = {}

for func in idautils.Functions():
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_LIB or flags & FUNC_THUNK:
		continue
	disam_addr = list(idautils.FuncItems(func))
	for curr_addr in disam_addr:
		op = None
		index = None
		# same as idc.GetOptype, just a different way of accessingthe types
		idaappi.decode_insn(curr_addr)
		if idaappi.cmd.Op1.type == idaappi.o_displ:
			op = 1
		if idaappi.cmd.Op2.type == idaappi.o_displ:
			op = 2
		if op == None:
			continue
		# idaapi.tag_remove(idaapi.ua_outop2(ea, n)) 获取操作数的字符串表示
		# 同 idc.GetOpnd(ea, n). 其实就是idc.GetOpnd(ea, n)的内部实现
		if "bp" in idaappi.tag_remove(idaappi.ua_outop2(curr_addr, 0)) or \
		   "bp" in idaappi.tag_remove(idaappi.ua_outop2(curr_addr, 1)):
			# ebp will return a negative number
			if op == 1:
				index = (~(int(idaappi.cmd.Op1.addr)-1)&0xFFFFFFFF)
			else:
				index = (~(int(idaappi.cmd.Op2.addr)-1)&0xFFFFFFFF)
		else:
			if op == 1:
				index = int(idaappi.cmd.Op1.addr)
			else:
				index = int(idaappi.cmd.Op2.addr)
		# create key for each unique displacement value
		if index:
			if displace.has_key(index) == False:
				displace[index] = []
			displace[index].append(curr_addr)


# 之后如果你想查找使用某个偏移量的所有地址, 如下:

for x in displace[0x130]:
	print hex(x), GetDisasm(x)

