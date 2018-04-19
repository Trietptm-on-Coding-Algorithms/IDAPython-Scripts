#encoding: utf-8
import idautils

# .text:0040108B                 lea     edi, [esp+68h+var_63]
ea = idc.ScreenEA()
print "0x%x %s" % (ea, ea) # 0x40108b 4198539
ea = here()
print "0x%x %s" % (ea, ea) # 0x40108b 4198539
print hex(MinEA()) # 0x401000
print hex(MaxEA()) # 0x409000

print idc.SegName(ea) # .text
print idc.GetDisasm(ea) # lea     edi, [esp+68h+var_63]
print idc.GetMnem(ea) # lea
print idc.GetOpnd(ea, 0) # edi
print idc.GetOpnd(ea, 1) # [esp+68h+var_63]

# 判断地址是否存在 -> 使用 idaapi.BADADDR
print hex(idaapi.BADADDR) # 0xffffffffL
if BADADDR == here():
	print "Error: invalid address"
	sys.exit(1)