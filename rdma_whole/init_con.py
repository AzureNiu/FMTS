# 该python程序用于设定P4代码中的定值

# 设置镜像方法的参数
mirror = bfrt.mirror.cfg
#mirror.delete(sid=1)
mirror.add_with_normal(sid=1,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=0,max_pkt_len=290)
mirror.add_with_normal(sid=2,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=1,max_pkt_len=162)
mirror.add_with_normal(sid=3,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=2,max_pkt_len=98)
mirror.add_with_normal(sid=4,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=3,max_pkt_len=66)
mirror.add_with_normal(sid=5,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=4,max_pkt_len=50)
mirror.add_with_normal(sid=6,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=5,max_pkt_len=42)
mirror.add_with_normal(sid=7,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=6,max_pkt_len=38)
mirror.add_with_normal(sid=8,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=7,max_pkt_len=36)
mirror.add_with_normal(sid=9,session_enable=True,direction="INGRESS",ucast_egress_port=160,ucast_egress_port_valid=True,egress_port_queue=8,max_pkt_len=35)

#pp = bfrt.code_merge_draft.pipe
pp = bfrt.nx_draft.pipe
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
table0.add_with_send_and_copy(ingress_port=144,port=136)
#table0.add_with_send_and_copy(ingress_port=144)
table0.add_with_send_and_copy(ingress_port=136,port=136)
#table0.add_with_send_and_copy(ingress_port=152,port=168)
#table0.add_with_send_and_copy(ingress_port=168,port=184)
#table0.add_with_send_and_copy(ingress_port=184,port=184)

# 设置子包长度计算参数
table1 = ingress.sub_table
table1.clear()
#table1.add_with_getSublen(total_len_start=0x0200+20,total_len_end=0xffff,   MATCH_PRIORITY=1,subLen=512)
#table1.add_with_getSublen(total_len_start=0x0100+20,total_len_end=0x01ff+20,MATCH_PRIORITY=1,subLen=256)
table1.add_with_getSublen(total_len_start=0x0100+20,total_len_end=0xffff,   MATCH_PRIORITY=1,subLen=256,sid=1,qid=0)
table1.add_with_getSublen(total_len_start=0x0080+20,total_len_end=0x00ff+20,MATCH_PRIORITY=1,subLen=128,sid=2,qid=1)
table1.add_with_getSublen(total_len_start=0x0040+20,total_len_end=0x007f+20,MATCH_PRIORITY=1,subLen=64, sid=3,qid=2)
table1.add_with_getSublen(total_len_start=0x0020+20,total_len_end=0x003f+20,MATCH_PRIORITY=1,subLen=32, sid=4,qid=3)
table1.add_with_getSublen(total_len_start=0x0010+20,total_len_end=0x001f+20,MATCH_PRIORITY=1,subLen=16, sid=5,qid=4)
table1.add_with_getSublen(total_len_start=0x0008+20,total_len_end=0x000f+20,MATCH_PRIORITY=1,subLen=8,  sid=6,qid=5)
table1.add_with_getSublen(total_len_start=0x0004+20,total_len_end=0x0007+20,MATCH_PRIORITY=1,subLen=4,  sid=7,qid=6)
table1.add_with_getSublen(total_len_start=0x0002+20,total_len_end=0x0003+20,MATCH_PRIORITY=1,subLen=2,  sid=8,qid=7)
table1.add_with_getSublen(total_len_start=0x0001+20,total_len_end=0x0001+20,MATCH_PRIORITY=1,subLen=1,  sid=9,qid=8)

egress = pp.Egress
#egress = bfrt.nx_rdma_16G.pipe.Egress
#egress = bfrt.nx_rdma_32G.pipe.Egress

# 设置4字节对齐填充的选择参数
table2 = egress.padding_table
table2.clear()
table2.add_with_padding2(subLen=2)
table2.add_with_padding1(subLen=1)