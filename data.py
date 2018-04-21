'''
返回 integer
idc.Byte(ea)
idc.Word(ea)
idc.Dword(ea)
idc.Qword(ea)
idc.GetFloat(ea)
idc.GetDouble(ea)
'''

# 使用 idc.GetManyBytes(ea, size, use_dbg=False) 获取某个地址开始的更多字节
for byte in idc.GetManyBytes(ea, 6):
	# 返回的是字节的字符表示
	print "0x%X" % ord(byte)

