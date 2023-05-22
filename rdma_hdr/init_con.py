# 该python程序用于设定P4代码中的定值

# 设置镜像方法的参数
mirror = bfrt.mirror.cfg
#mirror.delete(sid=1)
mirror.add_with_normal(sid=1,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=0,max_pkt_len=54)
mirror.add_with_normal(sid=2,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=1,max_pkt_len=42)

#pp = bfrt.code_merge_draft.pipe
pp = bfrt.nx_draft_hdr.pipe
#pp = bfrt.nx_rdma_16G.pipe
#pp = bfrt.nx_rdma_32G.pipe

ingress = pp.Ingress
#ingress = bfrt.nx_rdma_16G.pipe.Ingress
#ingress = bfrt.nx_rdma_32G.pipe.Ingress

# 设置基于输入端口的处理表参数
table0 = ingress.src_port_table
table0.clear()
table0.add_with_send(ingress_port=128,port=160)
table0.add_with_send(ingress_port=160,port=128)
table0.add_with_copyHdr(ingress_port=144)

# 设置子包长度计算参数
table1 = ingress.hdr_table
table1.clear()
table1.add_with_getHdrlen(protocol=6, subLen=20,sid=1,qid=0)
table1.add_with_getHdrlen(protocol=17,subLen=8, sid=2,qid=1)

egress = pp.Egress
#egress = bfrt.nx_rdma_16G.pipe.Egress
#egress = bfrt.nx_rdma_32G.pipe.Egress

# 设置4字节对齐填充的选择参数
table2 = egress.padding_table
table2.clear()