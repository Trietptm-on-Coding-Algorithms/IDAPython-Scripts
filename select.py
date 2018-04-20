#encoding: utf-8
import idautils
import idaapi

start = idc.SelStart()
print hex(start)
end = idc.SelEnd()
print hex(end)


# idaapi.read_selection()
# 返回一个元组, 第一个值为bool值, 判断是否读取成功
#             第二个值为开始地址, 最后一个值为结束地址

Worked, start, end = idaapi.read_selection()
# 注意在分析64为可执行文件时容易出错, 因为64位地址容易导致int的溢出