''' 
idc.PatchByte(ea, value)
idc.PatchWord(ea, value)
idc.PatchDword(ea, value)
'''

# 以下代码用于 patch 一个 xor 加密函数
start = idc.SelStart()
end = idc.SelEnd()

def xor(size, key, buff):
	for index in range(0, size):
		cur_addr = buff + index
		temp = idc.Byte(cur_addr) ^ key
		idc.PatchByte(cur_addr, temp)

xor(end-start, 0x30, start)
idc.GetString(start)