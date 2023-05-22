#include <core.p4>
#include <tna.p4>



/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
typedef bit<48> macAddr_t;	// mac地址
typedef bit<32> ip4Addr_t;	// ipv4地址

/* 用于处理加法进位的结构 */
struct b32_carry_t {
	bit<32> oldVal;	// 记录执行加法前低32位值
	bit<32> newVal;	// 记录执行加法后低32位值
}

struct pair_32 {
    bit<32> left;
    bit<32> right;
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* 用于处理子包拆分的额外辅助头 */
header extra_info_h {
	bit<15> type;
	/* 0为不需要额外处理的 
	 * 1为原像
	 * 3为镜像
	 * 其余数字为其他类型负载
	 */
	bit<1> idx;
	bit<16> subLen;
}
/* 镜像包头，同上 */
header mirror_h {
	bit<15>	type;
	bit<1>	idx;
	bit<16>	subLen;
}

/* 以太头 */
header ethernet_h {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16> etherType;
}

/* ipv4头 */
header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   total_len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* tcp头 */
header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

/* udp头，用于RoCE v2的RDMA封装 */
header udp_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<16> length;
	bit<16> checksum;
}

/* ib_bth头 */
header ib_bth_h {
    bit<8>  opcode;
    bit<1>  event;
    bit<1>  migReq;
    bit<2>  padCount;
    bit<4>  version;
    bit<16> pkey;
    bit<8>  resv8a;
    bit<24> dstQP;
    bit<1>  ackReq;
    bit<7>  resv7b;
    bit<24> psn;
}

/* ib_reth头 */
header ib_reth_h {
    bit<64> va;
    bit<32> rkey;
    bit<32> length;
}

header ib_aeth_h {
	bit<8> syndrome;
	bit<24> msgSeqNum;
}

/* 用于填充CRC */
header CRC_h {
	bit<32> val;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct ingress_header_t {
	extra_info_h info;	// 辅助头部信息
	ethernet_h ethernet;
	ipv4_h ipv4;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct ingress_metadata_t {
	MirrorId_t session_id;	// 使用的镜像ID
	mirror_h mirror_hdr;	// 镜像辅助头部信息
	bit<32> tmp0;	// 临时变量0
	bit<32> tmp1;	// 临时变量1
}

    /***********************  P A R S E R  **************************/

parser IngressParser (
	packet_in pkt,
	out ingress_header_t ig_hdr,
	out ingress_metadata_t ig_md,
	out ingress_intrinsic_metadata_t ig_intr_md)
{
	state start {
		pkt.extract(ig_intr_md);
		pkt.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(ig_hdr.ethernet);
		transition select(ig_hdr.ethernet.etherType) {
			0x0800: parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(ig_hdr.ipv4);
		transition accept;
	}

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress (
	inout ingress_header_t ig_hdr,
	inout ingress_metadata_t ig_md,
	in ingress_intrinsic_metadata_t ig_intr_md,
	in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
	/* 转发原包到回环端口，并将镜像包送往发送端口 */
	action copyHdr() {
		/* 设置镜像会话号 */
		//ig_md.session_id = sid;
		/* 设置镜像包类型 */
		ig_hdr.info.type = 1;
		ig_dprsr_md.mirror_type = 1;
		ig_dprsr_md.drop_ctl = 1;

		ig_md.mirror_hdr.setValid();
		ig_md.mirror_hdr.type = 2;
		ig_md.mirror_hdr.idx = 0;
	}

	/* 简单转发原包 */
	action send(PortId_t port) {
		ig_tm_md.ucast_egress_port = port;
		ig_hdr.info.type = 0;
	}

	/* 简单丢弃原包 */
	action drop() {
		ig_hdr.info.type = 0;
		ig_dprsr_md.mirror_type = 0;
		ig_dprsr_md.drop_ctl = 1;
	}

	/* 基于入端口的转发表 */
	table src_port_table {
		key = {
			ig_intr_md.ingress_port: exact;
		}
		actions = {
			send;
			copyHdr;
			drop;
		}
		size = 8;
		default_action = drop;
	}

	/* 基于totalLen确定当前划分子包长度 */
	action getHdrlen(bit<16> subLen, MirrorId_t sid, QueueId_t qid) {
		ig_md.mirror_hdr.subLen = subLen;
		/* 设置镜像会话号 */
		ig_md.session_id = sid;

		ig_tm_md.qid = qid;
	}

	table hdr_table {
		key = {
			ig_hdr.ipv4.protocol: exact;
		}
		actions = {
			getHdrlen;
			drop;
		}
		size = 8;
		default_action = drop;
	}

	table drop_table {
		actions = {
			drop;
		}
		size = 1;
		const default_action = drop;
	}

	/* 基于子包长度获取偏移量加法计算单元 */
	action initOffset() {
		ig_md.tmp0[15:0] = ig_hdr.info.subLen + 20;
		ig_md.tmp0[31:16] = 0;
	}
	table initOffset_table {
		actions = {
			initOffset;
		}
		size = 1;
		const default_action = initOffset;
	}

	/* 进位判断加法器
	 * 根据低32位的加法运算前后的对比，判断是否产生进位
	 * 进位返回1，不进位返回0
	 * 用于预测，所以为了避免判断的滞后性，设置初始值为276（最大的子包长度）
	 */
	Register<b32_carry_t, bit<1>>(1) offset_cr_reg;
	RegisterAction<b32_carry_t, bit<1>, bit<32>>(offset_cr_reg) offset_cr_action = {
		void apply(inout b32_carry_t reg, out bit<32> flag) {
			flag = 0;
			if (reg.oldVal >= 0x80000000 && reg.newVal < 0x80000000) {
				flag = 1;
				reg.oldVal = 276;
				reg.newVal = 276 + ig_md.tmp0;
			}
			else {
				reg.oldVal = reg.newVal;
				reg.newVal = reg.newVal + ig_md.tmp0;
			}
		}
	};
	action offset_cr() {
		ig_md.tmp0 = offset_cr_action.execute(0);
	}
	table offset_cr_table {
		actions = {
			offset_cr;
		}
		size = 1;
		const default_action = offset_cr;	
	}

	/* 高位判断加法器
	 * 根据高32位的值进行处理，判断当前拆分子包累积大小是否超过某个界限（本代码中为8G）
	 */
	Register<bit<32>, bit<1>>(1) offset_hi_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(offset_hi_reg) offset_hi_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			if (reg + ig_md.tmp0 == 0x00000002) {
				rst = 1;
				reg = 0;
			}
			else {
				rst = 0;
				reg = reg + ig_md.tmp0;
			}
        }
    };
	action offset_hi() {
		ig_md.tmp1 = offset_hi_action.execute(0);
	}
	table offset_hi_table {
		actions = {
			offset_hi;
		}
		size = 1;
		const default_action = offset_hi;
	}

	/* MR编号寄存器
	 * 用于记录当前使用的MR编号，在其中一块用完后，其取值会进行切换
	 */
	Register<bit<32>, bit<1>>(1) mr_reg;
	RegisterAction<bit<32>, bit<1>, bit<1>>(mr_reg) mr_choose_action = {
		void apply(inout bit<32> reg, out bit<1> rst) {
			if (ig_md.tmp1 == 1) {
				reg = reg^1;
			}
			rst = reg[0:0];
		}
	};
	action chooseMR() {
		ig_md.mirror_hdr.idx = mr_choose_action.execute(0);
	}
	table chooseMR_table {
		actions = {
			chooseMR;
		}
		size = 1;
		const default_action = chooseMR;
	}

	apply {
		ig_hdr.info.setValid();
		if (src_port_table.apply().hit) {
			/* 简单解析原像包本轮子包带来的偏移量增量 */
			if (ig_hdr.info.type == 1) {
				if (ig_hdr.ipv4.isValid()) {
					if (hdr_table.apply().hit) {	// 计算子包长度
						initOffset_table.apply();	// 设定加法单元
						offset_cr_table.apply();	// 计算进位情况
						offset_hi_table.apply();	// 计算高位情况
						chooseMR_table.apply();		// 查询MR编号
					}
				}
				else {
					drop_table.apply();
				}
			}
		}
	}
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser (
	packet_out pkt,
	inout ingress_header_t ig_hdr,
	in ingress_metadata_t ig_md,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
	Mirror() mirror;
	apply {
		if (ig_dprsr_md.mirror_type == 1) {
			/* 将镜像包转发到输出端口，并进行截断 */
			mirror.emit<mirror_h>(ig_md.session_id, ig_md.mirror_hdr);
		}
		pkt.emit(ig_hdr);
	}
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct egress_header_t {
	extra_info_h	info;   	// 辅助头部信息

	ethernet_h 		ethernet;
	ipv4_h 			newipv4;	// 用于RoCE v2的ipv4头
	udp_h 			udp;		// 用于RoCE v2的udp头
	ib_bth_h   		ib_bth;		// ib_bth头
    ib_reth_h  		ib_reth;	// ib_reth头

	ipv4_h 			oldipv4;	// 记录被拆分子包的ipv4信息头
	
	tcp_h 			tcp_payload;
	udp_h			udp_payload;
	ib_bth_h   		ib_bth_msg;	// 用于监控RDMA双端行为
	ib_aeth_h		ib_aeth;

	CRC_h 			ib_icrc;	// 用于RDMA的ICRC填充
	CRC_h 			eth_crc;	// 用于Ethernet的CRC填充
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct egress_metadata_t {
	bit<32> tmp0;	// 临时变量0
	bit<32> tmp1;	// 临时变量1
	bit<32> tmp2;
	bit<32> tmp3;
	bit<32> tmp4;
	bit<32> tmp5;
}

    /***********************  P A R S E R  **************************/

parser EgressParser (
	packet_in pkt,
	out egress_header_t eg_hdr,
	out egress_metadata_t eg_md,
	out egress_intrinsic_metadata_t eg_intr_md)
{
	state start {
		pkt.extract(eg_intr_md);
		//pkt.advance(PORT_METADATA_SIZE);
		transition parse_mirror;
	}

	state parse_mirror {
		pkt.extract(eg_hdr.info);
		transition parse_ethernet;
		/*transition select(eg_hdr.info.type[0:0]) {
			0: accept;
			default: parse_ethernet;
		}*/
	}

	state parse_ethernet {
		pkt.extract(eg_hdr.ethernet);
		//transition parse_ipv4;
		transition select(eg_hdr.info.type[1:0]) {
			0: parse_ipv4_0;
			2: parse_ipv4_2;
		}
	}

	state parse_ipv4_0 {
		pkt.extract(eg_hdr.oldipv4);
		transition select(eg_hdr.oldipv4.protocol) {
            17 : parse_udp;
            default : accept;
        }
	}

	state parse_udp {
		pkt.extract(eg_hdr.udp_payload);
		transition select(eg_hdr.udp_payload.dst_port) {
			4791: parse_ib_bth;
			default: accept;
		}
	}

	state parse_ib_bth {
		pkt.extract(eg_hdr.ib_bth_msg);
		transition select(eg_hdr.ib_bth_msg.opcode) {
			17: parse_ib_aeth;
			default: accept;
		}
	}

	state parse_ib_aeth {
		pkt.extract(eg_hdr.ib_aeth);
		transition accept;
	}

	state parse_ipv4_2 {
		pkt.extract(eg_hdr.oldipv4);
		transition select(eg_hdr.oldipv4.protocol) {
			6  : parse_tcp_hdr;
            17 : parse_udp_hdr;
            default : accept;
        }
	}

	state parse_tcp_hdr {
		pkt.extract(eg_hdr.tcp_payload);
		transition accept;
	}

	state parse_udp_hdr {
		pkt.extract(eg_hdr.udp_payload);
		transition accept;
	}
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress (
	inout egress_header_t eg_hdr,
	inout egress_metadata_t eg_md,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
	action NoPadding() {
		eg_hdr.oldipv4.total_len = eg_hdr.info.subLen+20;
	}
	table padding_table {
		actions = {
			NoPadding;
		}
		key = {
			eg_hdr.info.subLen: exact;
		}
		size = 2;
		default_action = NoPadding;
	}

	/* RDMA包的定值填充部分 */
	action setConst() {
		//eg_hdr.ethernet.dstAddr = 0xffffffffffff;
		//eg_hdr.ethernet.srcAddr = 0x1070fd31ec7d;
		eg_hdr.ethernet.etherType = 0x0800;

		eg_hdr.newipv4.setValid();
		eg_hdr.newipv4.version			= 4;
		eg_hdr.newipv4.ihl 				= 5;
		eg_hdr.newipv4.diffserv 		= 2;
		eg_hdr.newipv4.total_len 		= eg_hdr.info.subLen+80;
		//eg_hdr.newipv4.identification	= 0;
		eg_hdr.newipv4.flags 			= 2;
		eg_hdr.newipv4.fragOffset 		= 0;
		eg_hdr.newipv4.ttl 				= 64;
		eg_hdr.newipv4.protocol 		= 17;
		eg_hdr.newipv4.hdrChecksum     	= 0;
		//eg_hdr.newipv4.srcAddr 			= 0x0a000001;
		//eg_hdr.newipv4.dstAddr 			= 0x0a000002;

		eg_hdr.udp.setValid();
		//eg_hdr.udp.src_port = 0;
		eg_hdr.udp.dst_port = 4791;
		eg_hdr.udp.length = eg_hdr.info.subLen+60;
		eg_hdr.udp.checksum = 0;

		eg_hdr.ib_bth.setValid();
		eg_hdr.ib_bth.opcode = 10;
		eg_hdr.ib_bth.event = 0;
		eg_hdr.ib_bth.migReq = 1;
		eg_hdr.ib_bth.padCount = 0;
		eg_hdr.ib_bth.version = 0;
		eg_hdr.ib_bth.pkey = 0xffff;
		eg_hdr.ib_bth.resv8a = 0;
		//eg_hdr.ib_bth.dstQP = 0;
		eg_hdr.ib_bth.ackReq = 1;
		eg_hdr.ib_bth.resv7b = 0;
		//eg_hdr.ib_bth.psn = 0;

		eg_hdr.ib_reth.setValid();
		eg_hdr.ib_reth.va = 0;
		eg_hdr.ib_reth.rkey = 0;
		eg_hdr.ib_reth.length[15:0] = eg_hdr.info.subLen+20;
		eg_hdr.ib_reth.length[31:16] = 0;

		eg_hdr.ib_icrc.setValid();
		eg_hdr.ib_icrc.val[15:0] = eg_hdr.oldipv4.total_len-20;

		eg_hdr.eth_crc.setValid();
		eg_hdr.eth_crc.val = 0;

		eg_md.tmp0 = (bit<32>)eg_hdr.oldipv4.total_len;
	}
	table setConst_table {
		actions = {
			setConst;
		}
		size = 1;
		const default_action = setConst;
	}

	/* ipv4/RDMA包序号计数器 */
	Register<bit<32>, bit<1>>(1) seq_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(seq_reg) seqAdd_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			rst = reg;
			reg = reg+1;
        }
    };
	action seqAdd() {
		eg_md.tmp1 = seqAdd_action.execute(0);
		eg_hdr.newipv4.identification = (bit<16>)eg_md.tmp1;
		eg_hdr.ib_bth.psn = (bit<24>)eg_md.tmp1;
	}
	table seqAdd_table {
		actions = {
			seqAdd;
		}
		size = 1;
		const default_action = seqAdd;
	}

	RegisterAction<bit<32>, bit<1>, bit<32>>(seq_reg) seqMod_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			rst = reg; 
			reg = eg_md.tmp2;
        }
    };
	action seqMod() {
		eg_md.tmp3 = seqMod_action.execute(0);
	}
	table seqMod_table {
		actions = {
			seqMod;
		}
		size = 1;
		const default_action = seqMod;
	}


	/* 虚拟地址低位加法器（2组）
	 * 用于计算写入虚拟地址的低32位值
	 */
	Register<bit<32>, bit<1>>(2) va_lo_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(va_lo_reg) loAdd_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
            rst = reg;
			reg = reg + eg_md.tmp0;
        }
    };
	action loAdd() {
		eg_md.tmp1 = loAdd_action.execute(eg_hdr.info.idx);
		eg_hdr.ib_reth.va[31:0] = eg_md.tmp1;
	}
	table loAdd_table {
		actions = {
			loAdd;
		}
		size = 1;
		const default_action = loAdd;
	}

	/* 虚拟地址进位加法器（2组）
	 * 用于计算低32位地址是否发生进位
	 */
	Register<b32_carry_t, bit<1>>(2) va_cr_reg;
    RegisterAction<b32_carry_t, bit<1>, bit<32>>(va_cr_reg) crCal_action = {
        void apply(inout b32_carry_t reg, out bit<32> flag) {
			flag = 0;
			if (reg.oldVal >= 0x80000000 && reg.newVal < 0x80000000) {
				flag = 1;
			}
			reg.oldVal = reg.newVal;
			reg.newVal = reg.newVal + eg_md.tmp0;
        }
    };
	action crCal() {
		eg_md.tmp0 = crCal_action.execute(eg_hdr.info.idx);
	}
	table crCal_table {
		actions = {
			crCal;
		}
		size = 1;
		const default_action = crCal;
	}

	/* 虚拟地址高位加法器（2组）
	 * 用于计算写入虚拟地址的高32位值
	 */
	Register<bit<32>, bit<1>>(2) va_hi_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(va_hi_reg) hiAdd_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			reg = reg + eg_md.tmp0;
			rst = reg;
        }
    };
	action hiAdd() {
		eg_md.tmp1 = hiAdd_action.execute(eg_hdr.info.idx);
		eg_hdr.ib_reth.va[63:32] = eg_md.tmp1;
	}
	table hiAdd_table {
		actions = {
			hiAdd;
		}
		size = 1;
		const default_action = hiAdd;
	}

	/* RDMA的变量填充部分，数据来源于控制平面端文件 */
	action setVar(bit<48> dstEth, bit<48> srcEth, bit<32> srcIP, bit<32> dstIP, bit<16> srcPort, bit<24> dstQP, bit<32> rkey) {
		eg_hdr.ethernet.dstAddr = dstEth;
		eg_hdr.ethernet.srcAddr = srcEth;
		eg_hdr.newipv4.srcAddr = srcIP;
		eg_hdr.newipv4.dstAddr = dstIP;
		eg_hdr.udp.src_port = srcPort;
		eg_hdr.ib_bth.dstQP = dstQP;
		eg_hdr.ib_reth.rkey = rkey;
	}
	table setVar_table {
		actions = {
			NoAction;
			setVar;
		}
		key = { eg_hdr.info.type: exact; }
		size = 1;
		default_action = NoAction;
	}

	Register<b32_carry_t, bit<1>>(1) exsz_lo_reg;
	RegisterAction<b32_carry_t, bit<1>, bit<32>>(exsz_lo_reg) exsz_lo_action = {
		void apply(inout b32_carry_t reg, out bit<32> flag) {
			flag = 0;
			if (reg.oldVal >= 0x80000000 && reg.newVal < 0x80000000) {
				flag = 1;
			}
			reg.oldVal = reg.newVal;
			reg.newVal = reg.newVal + eg_md.tmp4;
        }
	};
	action exszCnt0() {
		eg_md.tmp4 = exsz_lo_action.execute(0);
	}

	Register<bit<32>, bit<1>>(1) exsz_hi_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(exsz_hi_reg) exsz_hi_action = {
        void apply(inout bit<32> reg) {
			reg = reg + eg_md.tmp4;
        }
    };
	action exszCnt1() {
		exsz_hi_action.execute(0);
	}

	Register<b32_carry_t, bit<1>>(1) outsz_lo_reg;
	RegisterAction<b32_carry_t, bit<1>, bit<32>>(outsz_lo_reg) outsz_lo_action = {
		void apply(inout b32_carry_t reg, out bit<32> flag) {
			flag = 0;
			if (reg.oldVal >= 0x80000000 && reg.newVal < 0x80000000) {
				flag = 1;
			}
			reg.oldVal = reg.newVal;
			reg.newVal = reg.newVal + eg_md.tmp5;
        }
	};
	action outszCnt0() {
		eg_md.tmp5 = outsz_lo_action.execute(0);
	}

	Register<bit<32>, bit<1>>(1) outsz_hi_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(outsz_hi_reg) outsz_hi_action = {
        void apply(inout bit<32> reg) {
			reg = reg + eg_md.tmp5;
        }
    };
	action outszCnt1() {
		outsz_hi_action.execute(0);
	}

	Register<bit<32>, bit<1>>(1) outpkt_reg;
	RegisterAction<bit<32>, bit<1>, bit<32>>(outpkt_reg) outpkt1_action = {
		void apply(inout bit<32> reg) {
			reg = reg + 1;
		}
	};
	action outpktCnt() {
		outpkt1_action.execute(0);
	}

 	/*Register<bit<32>, bit<1>>(1) ack_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_reg) ack_reg_action = {
        void apply(inout bit<32> reg) {
			reg = eg_md.tmp0;
        }
    };
	action ackUpdate() {
		ack_reg_action.execute(0);
	}*/

	Register<pair_32, bit<1>>(1) lost_reg;
	RegisterAction<pair_32, bit<1>, bit<32>>(lost_reg) lostCnt_action = {
		void apply(inout pair_32 reg) {
			reg.left = reg.left + 1;
			reg.right = reg.right + eg_md.tmp3;
		}
	};
	action lostCnt() {
		lostCnt_action.execute(0);
	}

	apply {
		if (eg_hdr.info.type == 2) {
			/* 如果是镜像，进行RDMA封装操作 */

			padding_table.apply();	// 4字节对齐填充预处理

			setConst_table.apply();	// 填充定值
			setVar_table.apply();	// 填充每次任务不同的特定变值

			seqAdd_table.apply();	// 计算序列号
			loAdd_table.apply();	// 计算低位
			crCal_table.apply();	// 计算进位
			hiAdd_table.apply();	// 计算高位

			eg_md.tmp4[31:16] = 0;
			eg_md.tmp4[15:0] = eg_hdr.info.subLen+20;
			exszCnt0();
			exszCnt1();
			eg_md.tmp5[31:16] = 0;
			eg_md.tmp5[15:0] = eg_hdr.info.subLen+20;
			outszCnt0();
			outszCnt1();

			//outpktCnt0();
			outpktCnt();
		}
		else if (eg_hdr.info.type == 0 && eg_hdr.ib_aeth.isValid()) {
			/*eg_md.tmp0 = (bit<32>)eg_hdr.ib_bth_msg.psn;
			eg_md.tmp0[31:24] = eg_hdr.ib_aeth.syndrome;
			ackUpdate();*/
			if (eg_hdr.ib_aeth.syndrome != 0) {
				eg_md.tmp2 = (bit<32>)eg_hdr.ib_bth_msg.psn;
				seqMod_table.apply();
				eg_md.tmp3 = eg_md.tmp3 - eg_md.tmp2;
				eg_md.tmp3 = eg_md.tmp3 & 0xffffff;
				lostCnt();
			}
		}
		eg_hdr.info.setInvalid();
	}
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser (
	packet_out pkt,
	inout egress_header_t eg_hdr,
	in egress_metadata_t eg_md,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
	Checksum() ipv4_csum;
	apply {
		if (eg_hdr.newipv4.isValid()) {
			// 计算生成RDMA包的ipv4的checksum
			eg_hdr.newipv4.hdrChecksum = ipv4_csum.update({
				eg_hdr.newipv4.version,
				eg_hdr.newipv4.ihl,
				eg_hdr.newipv4.diffserv,
				eg_hdr.newipv4.total_len,
				eg_hdr.newipv4.identification,
				eg_hdr.newipv4.flags,
				eg_hdr.newipv4.fragOffset,
				eg_hdr.newipv4.ttl,
				eg_hdr.newipv4.protocol,
				eg_hdr.newipv4.srcAddr,
				eg_hdr.newipv4.dstAddr
			});
		}
		pkt.emit(eg_hdr);
	}
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
	IngressParser(),
	Ingress(),
	IngressDeparser(),
	EgressParser(),
	Egress(),
	EgressDeparser()) pipe;

Switch(pipe) main;