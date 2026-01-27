package dmaAXI

import chisel3._
import chisel3.util.{Decoupled, Irrevocable}

// ==================== AXI4 Full接口定义 ====================

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