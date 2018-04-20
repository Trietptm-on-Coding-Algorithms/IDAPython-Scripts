#encoding: utf-8
import idautils
import idaapi
'''
SEARCH_UP 和 SEARCH_DOWN 用来指明搜索的方向
SEARCH_NEXT 用来获取下一个已经找到的对象
SEARCH_CASE 用来指明是否区分大小写
SEARCH_NOSHOW 用来指明是否显示搜索的进度
SEARCH_UNICODE 用于将所有搜索字符串视为Unicode
'''
pattern = '55 8B EC'
addr = MinEA()
for x in range(0, 5):
	# idc.FindBinary(ea, flag,searchstr, radix=16)
	addr = idc.FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, pattern)
if addr != idc.BADADDR:
	print hex(addr), idc.GetDisasm(addr)

curr_addr = MinEA()
end = MaxEA()
while curr_addr < end:
	# idc.FindText(ea,flag, y, x, searchstr)
	curr_addr = idc.FindText(curr_addr, SEARCH_DOWN, 0, 0, "Accept")
	if curr_addr == idc.BADADDR:
		break
	else:
		print hex(curr_addr), idc.GetDisasm(curr_addr)
		curr_addr = idc.NextHead(curr_addr)
'''
idc.isCode(f)
idc.isData(f)
idc.isTail(f)
idc.isUnknown(f)
idc.isHead(f)
'''

print hex(ea), idc.GetDisasm(ea)
print idc.isCode(idc.GetFlags(ea))


# idc.FindCode(ea, flag)
# 寻找被标志为代码的下一个地址, 可用于查找数据块末尾
print hex(ea), idc.GetDisasm(ea)
addr = idc.FindCode(ea, SEARCH_DOWN|SEARCH_NEXT)
print hex(addr), idc.GetDisasm(addr)

# idc.FindData(ea, flag)
# 类似 idc.FindCode(ea, flag)
print hex(ea), idc.GetDisasm(ea)
addr = idc.FindData(ea, SEARCH_UP|SEARCH_NEXT)
print hex(addr), idc.GetDisasm(addr)

# idc.FindUnexplored(ea, flag)
# 用于查找 IDA 未识别为代码或数据的字节地址
# 未知类型需要通过观察或脚本进一步手动分析
print hex(ea), idc.GetDisasm(ea)
addr = idc.FindUnexplored(ea, SEARCH_DOWN)
print hex(addr), idc.GetDisasm(addr)

# idc.FindExplored(ea, flag)
# 用于查找 IDA 标识为代码或数据的地址
addr = idc.FindExplored(ea, SEARCH_UP)
print hex(addr), idc.GetDisasm(addr)

# idc.FindImmediate(ea, flag, value)
# 返回一个元组. 第一项是地址, 第二项是第几个操作数
addr = idc.FindImmediate(MinEA(), SEARCH_DOWN, 0x343FD)
print addr
print "0x%x %s %x" % (addr[0], idc.GetDisasm(addr[0]), addr[1])

# 查找所有立即数的使用
addr = MinEA()
while True:
	addr, operand = idc.FindImmediate(addr, SEARCH_DOWN|SEARCH_NEXT, 0x7A)
	if addr != BADADDR:
		print hex(addr), idc.GetDisasm(addr), "Operand", operand
	else:
		break

