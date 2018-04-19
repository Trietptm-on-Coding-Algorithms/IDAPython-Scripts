#encoding: utf-8
import idautils

for func in idautils.Functions():
	print hex(func), idc.GetFunctionName(func)
	'''
	0x401000 _WinMain@16
	0x401020 DialogFunc
	0x401080 sub_401080
	0x401150 _strncmp
	0x401188 start
	0x40127e __amsg_exit
	0x4012a3 _fast_error_exit
	0x4012c7 __cinit
	0x4012f4 _exit
	0x401305 __exit
	0x401316 _doexit
	0x4013af __initterm
	0x4013c9 __XcptFilter
	0x40150a _xcptlookup
	0x40154d __wincmdln
	0x4015a5 __setenvp
	0x40165e __setargv
	0x4016f7 _parse_cmdline
	0x4018ab ___crtGetEnvironmentStringsA
	0x4019dd __ioinit
	0x401b88 sub_401B88
	0x401bb5 sub_401BB5
	0x401cfd sub_401CFD
	0x401d5c __global_unwind2
	0x401d7c __unwind_handler
	0x401d9e __local_unwind2
	0x401e06 __abnormal_termination
	0x401e32 __NLG_Notify
	0x401e54 __except_handler3
	0x401f11 __seh_longjmp_unwind@4
	0x401f2c __FF_MSGBANNER
	0x401f65 sub_401F65
	0x4020b8 __ismbblead
	0x4020c9 _x_ismbbtype
	0x4020fa __setmbcp
	0x402293 _getSystemCP
	0x4022dd _CPtoLCID
	0x402310 _setSBCS
	0x402339 _setSBUpLow
	0x4024be ___initmbctable
	0x4024da sub_4024DA
	0x402550 _strcpy
	0x402560 _strcat
	0x402640 _malloc
	0x402652 __nh_malloc
	0x40267e sub_40267E
	0x402700 _strlen
	0x402780 _memcpy
	0x402ab5 _strtol
	0x402acc _strtoxl
	0x402cf0 _strchr
	0x402db0 _strstr
	0x402e30 __alloca_probe
	0x402e5f ___sbh_heap_init
	0x402ea7 ___sbh_find_block
	0x402ed2 sub_402ED2
	0x4031fb ___sbh_alloc_block
	0x403504 ___sbh_alloc_new_region
	0x4035b5 ___sbh_alloc_new_group
	0x4036b0 sub_4036B0
	0x4037f4 sub_4037F4
	0x40384a sub_40384A
	0x40390c sub_40390C
	0x403963 sub_403963
	0x4039a8 sub_4039A8
	0x403bb0 sub_403BB0
	0x403cd4 ___crtMessageBoxA
	0x403d60 _strncpy
	0x403e5e ___crtLCMapStringA
	0x404082 _strncnt
	0x4040ad ___crtGetStringTypeA
	0x4041f6 __callnewh
	0x404211 _toupper
	0x4042dd __isctype
	0x404360 _memcpy_0
	0x4046a0 _memset
	0x4046f8 RtlUnwind
	'''

# .text:0040108B                 lea     edi, [esp+68h+var_63]
ea = idc.ScreenEA()
print "0x%x %s" % (ea, ea) # 0x40108b 4198539

func = idaapi.get_func(ea)
print type(func) # <class 'idaapi.func_t'>

# Start: 0x401080, End: 0x40114d
print "Start: 0x%x, End: 0x%x" % (func.startEA, func.endEA)

print dir(func)
'''
['__class__', '__del__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__getattribute__', '__gt__', '__hash__', '__init__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__swig_destroy__', '__weakref__', '_print', 'analyzed_sp', 'argsize', 'clear', 'color', 'compare', 'contains', 'does_return', 'empty', 'endEA', 'extend', 'flags', 'fpd', 'frame', 'frregs', 'frsize', 'intersect', 'is_far', 'llabelqty', 'llabels', 'overlaps', 'owner', 'pntqty', 'points', 'referers', 'refqty', 'regargqty', 'regargs', 'regvarqty', 'regvars', 'size', 'startEA', 'tailqty', 'tails', 'this', 'thisown']
'''


# 获取函数的边界地址
ea = here()
start = idc.GetFunctionAttr(ea, FUNCATTR_START)
end = idc.GetFunctionAttr(ea, FUNCATTR_END)
cur_addr = start
while cur_addr <= end:
	print hex(cur_addr), idc.GetDisasm(cur_addr)
	# idc.NextHead()不停的获取下一条指令的地址, 直到函数的结束地址才停止
	# 这种方法的缺陷是, 它依赖于指令被包含在函数开始和结束的边界内
	# 因为函数的所有指令可能并不是线性的. 它可能会通过jmp跳出函数边界
	# 最好用 idautils.FuncItems(ea)来循环函数内的指令
	cur_addr = idc.NextHead(cur_addr, end)

'''
GetFunctionFlags(ea)用于检索关于函数的信息
  例如函数是否有返回值
  一共有9个可能的标志
'''
# 获取ea所在函数的标志
ea = here()
func = idaapi.get_func(ea)

flags = idc.GetFunctionFlags(func.startEA)
if flags & FUNC_NORET:
	# 函数是否有返回值. FUNC_NORET本身值为1
	print hex(func), "FUNC_NORET"
if flags & FUNC_FAR:
	# 这个标志非常少见, 标志程序是否使用分段内存, 值为2
	print hex(func), "FUNC_FAR"
if flags & FUNC_LIB:
	# 表示用于寻找库函数的代码. 
	# 识别库函数代码是非常有必要的. 因为我们会在分析时将其跳过.
	# 值为4
	print hex(func), "FUNC_LIB"
if flags & FUNC_STATIC:
	# 标志函数是否为静态函数
	# 静态函数默认为全局的
	print hex(func), "FUNC_STATIC"
if flags & FUNC_FRAME:
	# 标志函数是否使用了ebp寄存器(栈帧指针)
	print hex(func), "FUNC_FRAME"
if flags & FUNC_USERFAR:
	# 非常少见. "user has specified farness of the function", 值为32
	print hex(func), "FUNC_USERFAR"
if flags & FUNC_HIDDEN:
	# 该标志意味着函数是隐藏的, 需要展开才能查看
	# 如果我们跳转到一个标记为HIDDEN的地址的话, 它会自动展开
	print hex(func), "FUNC_HIDDEN"
if flags & FUNC_THUNK:
	# 标志这个函数是否是一个thunk函数
	# thunk函数表示的是一个简单的跳转函数
	print hex(func), "FUNC_THUNK"
if flags & FUNC_BOTTOMBP:
	# 标志函数中帧指针(ebp)是否等于堆栈指针(esp)
	print hex(func), "FUNC_BOTTOMBP"