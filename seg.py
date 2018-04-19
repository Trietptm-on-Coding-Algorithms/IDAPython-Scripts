#encoding: utf-8
import idautils

# .text:0040108B                 lea     edi, [esp+68h+var_63]
ea = idc.ScreenEA()
print "0x%x %s" % (ea, ea) # 0x40108b 4198539

# 遍历所有段
'''
.text 0x401000 0x405000
.idata 0x405000 0x4050b0
.rdata 0x4050b0 0x406000
.data 0x406000 0x409000
'''
for seg in idautils.Segments():
    print idc.SegName(seg), hex(idc.SegStart(seg)), hex(idc.SegEnd(seg))

print hex(idc.NextSeg(ea)) # 0x405000
idata_seg_selector = idc.SegByName('.data')
idata_seg_startea = idc.SegByBase(idata_seg_selector)
idata_seg_endea = idc.SegEnd(idata_seg_startea)
print hex(idata_seg_startea) # 0x406000
print hex(idata_seg_endea) # 0x409000