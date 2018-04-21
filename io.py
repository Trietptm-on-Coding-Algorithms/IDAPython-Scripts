'''
AskFile(forsave, mask, prompt)
  forsave 为0, 弹出对话框打开文件. 为1, 弹出对话框保存文件
  mask 指定文件后缀或模式, 如"*.dll"
  prompt 窗口名称
'''

import sys
import idaapi
class IO_DATA():
	def __init__(self):
		self.start = SelStart()
		self.end = SelEnd()
		self.buffer = ''
		self.ogLen = None
		self.status = True
		self.run()
	def checkBounds(self):
		if self.start is BADADDR or self.end is BADADDR:
			self.status = False
	def getData(self):
		'''get data between start and end put them into object.buffer'''
		self.ogLen = self.end - self.start
		self.buffer = ''
		try:
			for byte in idc.GetManyBytes(self.start, self.ogLen):
			self.buffer = self.buffer + byte
		except:
			self.start = False
		return 
def run(self):
	''' bascally main'''
	if self.status == False:
		sys.stdout.write('ERROR: Please select valid data\n')
		return 
	self.getData()
def patch(self, temp=None):
	''' patch idb with data in object.buffer'''
	if temp != None:
		self.buffer = temp
		for index, byte in enumerate(self.buffer):
			idc.PatchByte(self.start+index, ord(byte))
def importb(self):
	''' import file to save to buffer'''
	fileName = idc.AskFile(0 "*.*", "Import File")
	try:
		self.buffer = open(fileName, 'rb').read()
	except:
		self.stdout.write('ERROR: Cannot access file')
def export(self):
	''' save the selected buffer to a file '''
	exportFile = idc.AskFile(1, "*.*", "Export Buffer")
	f = open(exportFile, 'wb')
	f.write()
	f.close()
def stats(self):
	print "start: %s" % hex(self.start)
	print "end: %s" % hex(self.end)
	print "len: %s" % hex(len(self.buffer))



# 如何使用 IO_DATA 类
f = IO_DATA()
F.stats()