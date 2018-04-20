#encoding: utf-8
import idautils

for func in idautils.Functions():
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_LIB or flags & FUNC_THUNKL:
		continue
	dism_addr = list(idautils.FuncItems(func))
	for ea in dism_addr:
		if idc.GetMnem(ea) == "xor":
			if idc.GetOpnd(ea, 0) == idc.GetOpnd(ea, 1):
				comment = "%s = 0" % (idc.GetOpnd(ea, 0))
				idc.MakeComm(ea, comment)


# 获取注释 GetCommentEx(ea, repeatable)
idc.GetCommentEx(ea, False)
# 获取重复性注释
idc.GetCommentEx(ea, True)

# 注释函数
idc.SetFunctionCmt(ea, cmt, repeatable)
# 获取函数注释
idc.GetFunctionCmt(ea, repeatable)

