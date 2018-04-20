#encoding: utf-8
import idautils
import idaapi

wf_addr = idc.LocByName("WriteFile")
print hex(wf_addr), idc.GetDisasm(wf_addr) # 0x405070 extrn WriteFile:dword

# 0x4020af call    ds:WriteFile
for addr in idautils.CodeRefsTo(wf_addr, 0):
	print hex(addr), idc.GetDisasm(addr) 



# 查找数据的交叉引用
print hex(ea), idc.GetDisasm(ea)
for addr in idautils.DataRefsTo(ea):
	print hex(addr), idc.GetDisasm(addr)

# 获取所有交叉引用地址和调用地址
# idautils.XrefsTo(ea, flags=0)
# idautils.XrefsFrom(ea, flags=0)
print hex(ea), idc.GetDisasm(ea)
# XrefsTo(ea, flag) 中flag设为1, 可以略过正常指令流程造成的交叉引用
for xref in idautils.XrefsTo(ea, 1):
	print xref.type, idautils.XrefTypeName(xref.type), \
	      hex(xref.frm), hex(xref.to), xref.iscode
	print hex(xref.frm), idc.GetDisasm(xref.frm)

# idautils.XrefTypeName(xref.type)用来打印表示该类型的含义
'''
0 = 'Data_Unknown'
1 = 'Data_Offset'
2 = 'Data_Write'
3 = 'Data_Read'
4 = 'Data_Text'
5 = 'Data_Informational'
16 = 'Code_Far_Call'
17 = 'Code_Near_Call'
18 = 'Code_Far_Jump'
19 = 'Code_Near_Jump'
20 = 'Code_User'
21 = 'Ordinary_Flow'
'''

'''
因为 idautils.CodeRefsTo(ea, flow)的限制:
    动态导入并手动重命名的 API 不会显示为代码交叉引用 
所以如下将地址重命名为 RtlCompareMemory 并不能标记为交叉引用
'''
print hex(ea)
idc.MakeName(ea, "RtlCompareMemory")
for addr in idautils.CodeRefsTo(ea, 0):
	print hex(addr), idc.GetDisasm(addr)


# 使用 idautils.XrefsTo(ea,flow)来获取它所有的交叉引用
print hex(ea)
idc.MakeName(ea, "RtlCompareMemory")
for xref in idautils.XrefsTo(ea, 1):
	print xref.type, idautils.XrefTypeName(xref.type), \
		  hex(xref.frm), hex(xref.to), xref.iscode

# 获取所有的交叉引用会有重复
# 利用 set 来精简
def get_to_xrefs(ea):
	xref_set = set([])
	for xref in idautils.XrefsTo(ea, 1):
		xref_set.add(xref.frm)
	return xref_set
def get_frm_xrefs(ea):
	xref_set = set([])
	for xref in idautils.XrefsFrom(ea, 1):
		xref_set.add(XrefsTo)