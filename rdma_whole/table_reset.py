# 该python程序用于监视交换机上的MR切换情况，并适时重置表项
# 然后通过TCP和写入端建立通信，告知MR切换信息

import sys
import threading

# 读取文件中的虚拟地址信息，用于重置表项
f = open('/root/niux/rdma_whole/rdma_params.txt')
#for i in range(3):
f.readline()
first_psn = int(f.readline().split()[1])
f.readline()
va_lo = int(f.readline().split()[1])
va_hi = []
va_hi.append(int(f.readline().split()[1]))
va_hi.append(int(f.readline().split()[1]))
f.close()

flag = True

pp = bfrt.nx_draft.pipe
#pp = bfrt.nx_rdma_16G.pipe
#pp = bfrt.nx_rdma_32G.pipe

ingress = pp.Ingress
egress = pp.Egress

reg = [ ingress.mr_reg,
	    egress.va_lo_reg,
	    egress.va_cr_reg,
		egress.va_hi_reg,
	   	egress.lost_reg,
	   	egress.seq_reg,
		egress.outpkt_reg,
		egress.outsz_lo_reg,
		egress.exsz_lo_reg,
		egress.outsz_hi_reg,
		egress.exsz_hi_reg]

old_stdout = sys.stdout
old_stderr = sys.stderr
devnull = open('/dev/null','w')

# 监听函数，用于监视MR的编号变化，并重置表项和发送通知
def listen_fun(devnull, reg, old_stdout, old_stderr, va_lo, va_hi):
	import time
	import socket

	# 创建TCP连接
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_ip = "162.105.146.62"
	server_port = 53101
	client.connect((server_ip, server_port))
	print("TCP Connection: OK")

	global flag
	mr = 0
	nak_cnt = 0
	lost_cnt = 0

	while flag:
		# 关闭标准输出的信息打印
		sys.stdout = devnull
		#sys.stderr = devnull

		# 每0.1s查询一次MR编号是否发生变化
		reg[0].operation_register_sync()
		
		reg[4].operation_register_sync()
		reg[5].operation_register_sync()

		time.sleep(0.001)
		now_mr = reg[0].get(0).data[b'Ingress.mr_reg.f1'][1]
		'''
		ack_info = reg[4].get(0).data[b'Egress.ack_reg.f1'][1]
		ack_op = ack_info>>24
		ack_psn = ack_info&0x00ffffff
		now_psn = reg[5].get(0).data[b'Egress.seq_reg.f1'][1]
		'''
		# 开启标准输出的信息打印
		sys.stdout = old_stdout
		#sys.stderr = old_stderr

		if mr != now_mr:
			# MR编号发生变化，发送信息通知写入端，并重置交换机上表项
			msg = 'Switched: From {} to {}\0'.format(mr, now_mr)
			client.send(msg.encode(encoding='ascii'))
			print(msg)
			reg[1].mod(mr, va_lo)
			reg[2].mod(mr, va_lo, va_lo)
			reg[3].mod(mr, va_hi[mr])
			mr = now_mr
		'''
		if ack_op != 0:
			reg[4].mod(0, 0)
			reg[5].mod(0, ack_psn)
			print('NAK at {}'.format(ack_psn))
			nak_cnt += 1
			lost_cnt += (now_psn-ack_psn)&0x00ffffff
		'''	
		#elif ack_psn != 0:
			#print('ACK at {}'.format(ack_psn))
			#reg[4].mod(0, 0)

	# 关闭标准输出的信息打印
	sys.stdout = devnull
	#sys.stderr = devnull

	reg[1].operation_register_sync()
	reg[3].operation_register_sync()
	reg[4].operation_register_sync()
	reg[5].operation_register_sync()
	reg[6].operation_register_sync()
	reg[7].operation_register_sync()
	reg[8].operation_register_sync()
	reg[9].operation_register_sync()
	reg[10].operation_register_sync()
	time.sleep(0.1)
	now_va_lo = reg[1].get(mr).data[b'Egress.va_lo_reg.f1'][1]
	now_va_hi = reg[3].get(mr).data[b'Egress.va_hi_reg.f1'][1]
	now_psn = reg[5].get(0).data[b'Egress.seq_reg.f1'][1]
	outpkt = [0,0]
	outpkt[0] = reg[6].get(0).data[b'Egress.outpkt_reg.left'][1]
	outpkt[1] = reg[6].get(0).data[b'Egress.outpkt_reg.right'][1]
	nak_cnt = reg[4].get(0).data[b'Egress.lost_reg.left'][1]
	lost_cnt = reg[4].get(0).data[b'Egress.lost_reg.right'][1]
	outsz_lo = [0,0]
	outsz_lo[0] = reg[7].get(0).data[b'Egress.outsz_lo_reg.oldVal'][1]
	outsz_lo[1] = reg[7].get(0).data[b'Egress.outsz_lo_reg.newVal'][1]
	exsz_lo = [0,0]
	exsz_lo[0] = reg[8].get(0).data[b'Egress.exsz_lo_reg.oldVal'][1]
	exsz_lo[1] = reg[8].get(0).data[b'Egress.exsz_lo_reg.newVal'][1]
	outsz_hi = reg[9].get(0).data[b'Egress.outsz_hi_reg.f1'][1]
	exsz_hi = reg[10].get(0).data[b'Egress.exsz_hi_reg.f1'][1]
	if outsz_lo[0] > outsz_lo[1]:
		outsz_hi += 1
	if exsz_lo[0] > exsz_lo[1]:
		exsz_hi += 1
	outsz = (outsz_hi<<32)+outsz_lo[1]
	exsz = (exsz_hi<<32)+exsz_lo[1]

	# 开启标准输出的信息打印
	sys.stdout = old_stdout
	#sys.stderr = old_stderr

	msg = 'Over\0'
	client.send(msg.encode(encoding='ascii'))
	print(msg)

	now_va = int('{:x}{:08x}'.format(now_va_hi, now_va_lo), 16)
	msg = str(now_va)+'\0'
	print(msg)
	client.send(msg.encode(encoding='ascii'))
	print('The end of data is at {:x} of MR[{}]\n'.format(now_va, mr))
	
	'''
	print('The count of NAK is {}'.format(nak_cnt))
	print('The count of lost pkts is {}'.format(lost_cnt))
	print('The last ack psn is {}'.format(now_psn))
	'''

	'''
	i = 0

	num_in = [11626492,11469736,13705555,9240723,9915680]
	byte_in = [7273137121,7523434356,8473681892,5657127858,5584818769]

	print('总包数量: {}/{} {}'.format(outpkt[1], num_in[i], num_in[i]-(outpkt[1])))
	'''

	print('内部完整处理包数量: {}'.format(outpkt[1]))

	#print('输出包原大小: {}'.format(byte_in[i]))
	print('内部生成字节: {}'.format(exsz))
	print('输出字节: {}'.format(outsz))
	print('输出包数: {}\n'.format(outpkt[0]))

	print('NAK数量为: {}'.format(nak_cnt))
	print('NAK带来的丢包数量为: {}'.format(lost_cnt))
	scc_cnt = outpkt[0]-lost_cnt
	print('成功收到ACK的包为: {}'.format(scc_cnt))
	
	client.close()

# 退出函数，用于判断接收和处理退出指令
def exit_fun():
	global flag

	while flag:
		cmd = input()
		if cmd == 'quit':
			flag = False

# 同时创建两个线程，分别用于监听MR和监听退出信号
thread1 = threading.Thread(target=listen_fun, args=(devnull, reg, old_stdout, old_stderr, va_lo, va_hi, ))
thread2 = threading.Thread(target=exit_fun)
thread1.start()
thread2.start()
thread1.join()
print('Thread1: OK')
thread2.join()
print('Thread2: OK')

devnull.close()