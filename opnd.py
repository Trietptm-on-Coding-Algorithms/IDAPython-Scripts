#encoding: utf-8
import idautils

ea = here()
print hex(ea), idc.GetDisasm(ea)

'''
o_void:
	如果指令没有任何操作数, 返回 0
	0xa09166 retn
o_reg:
	如果操作数是寄存器, 则返回 1
	0xa09163 pop edi
o_mem:
	如果操作数是直接寻址的内存, 返回 2, 这种类型对寻找DATA的引用非常有帮助
	0xa05d86 cmp ds:dword_A152B8, 0
o_phrase:
	如果操作数是利用基址寄存器和变址寄存器的寻址操作的话, 返回 3
	0x1000b8c2 mov [edi+ecx], eax
o_displ:
	如果操作数是利用寄存器和位移的寻址操作的话, 返回 4, 位移指的是像如下代码中的0x18, 这在获取结构体中的某个数据是非常常见的
	0xa05dc1 mov eax, [edi+18h]		(idc.GetOpType(ea, 1))
o_imm:
	如果操作数是一个立即数, 返回 5
	0xa05da1 add esp, 0Ch			(idc.GetOpType(ea, 1))
o_far:
	这种返回类型在x86和x86_64的逆向中不常见. 它用来判断直接访问远端地址的操作数, 返回 6
o_near:
	这种返回类型在x86和x86_64的逆向中不常见. 它用来判断直接访问近端地址的操作数, 返回 7
'''
print idc.GetOpType(ea, 0)

