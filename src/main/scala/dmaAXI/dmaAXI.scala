package dmaAXI

import chisel3._
import chisel3.util.{Decoupled, Irrevocable}

// ==================== AXI4 Full接口定义 ====================
class AXI4WrAddrChannel(addrWidth: Int) extends Bundle {
  val awaddr  = UInt(addrWidth.W)
  val awburst = UInt(2.W)  // 00=FIXED, 01=INCR, 10=WRAP
  val awlen   = UInt(8.W)  // Burst长度 (0=1beat, 7=8beats)
  val awsize  = UInt(3.W)  // 数据宽度 (3=32bit,5=256bit)
  val awvalid = Output(Bool())
  val awready = Input(Bool())
}

class AXI4WrDataChannel(dataWidth: Int) extends Bundle {
  val wdata  = UInt(dataWidth.W)
  val wstrb  = UInt((dataWidth/8).W)
  val wlast  = Bool()
  val wvalid = Output(Bool())
  val wready = Input(Bool())
}

class AXI4WrRespChannel extends Bundle {
  val bresp  = Input(UInt(2.W))
  val bvalid = Input(Bool())
  val bready = Output(Bool())
}

class AXI4RdAddrChannel(addrWidth: Int) extends Bundle {
  val araddr  = UInt(addrWidth.W)
  val arburst = UInt(2.W)
  val arlen   = UInt(8.W)
  val arsize  = UInt(3.W)
  val arvalid = Output(Bool())
  val arready = Input(Bool())
}

class AXI4RdDataChannel(dataWidth: Int) extends Bundle {
  val rdata  = Input(UInt(dataWidth.W))
  val rresp  = Input(UInt(2.W))
  val rlast  = Input(Bool())
  val rvalid = Input(Bool())
  val rready = Output(Bool())
}

// 完整AXI4接口
class AXI4Intf(addrWidth: Int = 32, dataWidth: Int = 256) extends Bundle {
  val aw = new AXI4WrAddrChannel(addrWidth)
  val w  = new AXI4WrDataChannel(dataWidth)
  val b  = new AXI4WrRespChannel()
  val ar = new AXI4RdAddrChannel(addrWidth)
  val r  = new AXI4RdDataChannel(dataWidth)
}

// 写通道视图（Chisel 7.0 DataView新路径）
class AXI4WrIntfView(addrWidth: Int, dataWidth: Int) extends Bundle {
  val aw = new AXI4WrAddrChannel(addrWidth)
  val w  = new AXI4WrDataChannel(dataWidth)
  val b  = new AXI4WrRespChannel()
}

// 读通道视图
class AXI4RdIntfView(addrWidth: Int, dataWidth: Int) extends Bundle {
  val ar = new AXI4RdAddrChannel(addrWidth)
  val r  = new AXI4RdDataChannel(dataWidth)
}

// Chisel 7.0：显式声明DataView类型（新包路径）
// DataView-based implicit views removed for compatibility with this Chisel version