#encoding: utf-8
import idautils

ea = here();
# idautils.FuncItems()获取函数中所有指令地址的集合
dism_addr = list(idautils.FuncItems(ea))
print type(dism_addr)
print dism_addr
for line in dism_addr: 
	print hex(line), idc.GetDisasm(line)
	
# 0x40108b lea     edi, [esp+68h+var_63]
print hex(ea), idc.GetDisasm(ea)
next_instr = idc.NextHead(ea)
# 0x40108f mov     [esp+68h+String], 0
print hex(next_instr), idc.GetDisasm(next_instr)
prev_instr = idc.PrevHead(ea)
# 0x401089 xor     eax, eax
print hex(prev_instr), idc.GetDisasm(prev_instr)
# 0x40108c
print hex(idc.NextAddr(ea))
# 0x40108a
print hex(idc.PrevAddr(ea))



