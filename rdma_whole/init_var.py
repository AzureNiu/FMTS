# 该python程序用于设定P4代码中的变值
#pp = bfrt.code_merge_draft.pipe
pp = bfrt.nx_draft.pipe
#pp = bfrt.nx_rdma_16G.pipe
#pp = bfrt.nx_rdma_32G.pipe

ingress = pp.Ingress
#ingress = bfrt.nx_rdma_16G.pipe.Ingress
#ingress = bfrt.nx_rdma_32G.pipe.Ingress

# 初始化ingress中的偏移量进位、高位以及MR编号的初值
reg0 = ingress.offset_cr_reg
reg0.mod(0, 276, 276)
#reg0.mod(0, 0xfffffe00, 0xfffffe00)

reg1 = ingress.offset_hi_reg
#reg1.mod(0, 0)
reg1.mod(0, 0)

reg2 = ingress.mr_reg
reg2.mod(0, 0)

# 读取文件中的RDMA参数 
f = open('/root/niux/rdma_whole/rdma_params.txt')

dstQP = int(f.readline().split()[1])
seq = int(f.readline().split()[1])
srcPort = int(f.readline().split()[1])
va_lo = int(f.readline().split()[1])
va_hi_0 = int(f.readline().split()[1])
va_hi_1 = int(f.readline().split()[1])

rKey = int(f.readline().split()[1])
f.close()

# 填写源和目的的Eth和IP信息
dstEth = 0x1070fd31e6cd
#srcEth = 0x1070fd31e6cd
srcEth = 0x08c0ebf5e533
srcIP = 0x0a000006
#srcIP = 0x0a000003
dstIP = 0x0a000002
#srcPort = 51770
#dstQP = 0x1dfa
#rKey = 0x56c6b

egress = pp.Egress
#egress = bfrt.nx_rdma_16G.pipe.Egress
#egress = bfrt.nx_rdma_32G.pipe.Egress

# 将包序号和虚拟地址填入相应寄存器
table3 = egress.setVar_table
table3.clear()
table3.add_with_setVar(type=3,dstEth=dstEth,srcEth=srcEth,srcIP=srcIP,dstIP=dstIP,
							srcPort=srcPort,dstQP=dstQP,rkey=rKey)

#seq = 7347838
reg3 = egress.seq_reg
reg3.mod(0, seq)

#va_lo = 0x97e56010
#va_hi = 0x7f7c

reg4 = egress.va_lo_reg
reg4.mod(0, va_lo)
reg4.mod(1, va_lo)

reg5 = egress.va_cr_reg
reg5.mod(0, va_lo, va_lo)
reg5.mod(1, va_lo, va_lo)

reg6 = egress.va_hi_reg
reg6.mod(0, va_hi_0)
reg6.mod(1, va_hi_1)

reg7 = egress.lost_reg
reg7.mod(0, 0, 0)

reg8 = egress.outpkt_reg
reg8.mod(0, 0, 0)

reg9 = egress.outsz_lo_reg
reg9.mod(0, 0, 0)

reg10 = egress.exsz_lo_reg
reg10.mod(0, 0, 0)

reg11 = egress.outsz_hi_reg
reg11.mod(0, 0)

reg12 = egress.exsz_hi_reg
reg12.mod(0, 0)