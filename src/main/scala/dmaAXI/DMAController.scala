package dmaAXI

import chisel3._
import chisel3.util._

// ==================== APB4接口定义 ====================
class APB4IO extends Bundle {
  val PADDR   = Input(UInt(32.W))
  val PPROT   = Input(UInt(3.W))
  val PSEL    = Input(Bool())
  val PENABLE = Input(Bool())
  val PWRITE  = Input(Bool())
  val PWDATA  = Input(UInt(32.W))
  val PSTRB   = Input(UInt(4.W))
  val PRDATA  = Output(UInt(32.W))
  val PREADY  = Output(Bool())
  val PSLVERR = Output(Bool())
}

// ==================== DMA配置寄存器 ====================
object DmaRegs {
  // 寄存器偏移（Int常量）
  val SRC_ADDR   = 0x00  // 源地址 (32bit)
  val DST_ADDR   = 0x04  // 目的地址 (32bit)
  val LENGTH     = 0x08  // 搬移长度（字节）
  val CTRL       = 0x0C  // 控制：bit0=启动, bit1=完成, bit2=错误
  val STATUS     = 0x10  // 状态：bit0=忙, bit1=FIFO高水位

  // APB地址选择（Chisel 7.0语法不变）
  val SRC_ADDR_SEL = (SRC_ADDR).U(32.W)(5, 2)
  val DST_ADDR_SEL = (DST_ADDR).U(32.W)(5, 2)
  val LENGTH_SEL   = (LENGTH).U(32.W)(5, 2)
  val CTRL_SEL     = (CTRL).U(32.W)(5, 2)
  val STATUS_SEL   = (STATUS).U(32.W)(5, 2)
}

// ==================== 4K边界检查工具 ====================
object DmaUtils {
  def getSafeBurstLen(startAddr: UInt, remainingBytes: UInt, beatBytes: Int = 32): UInt = {
    val pageMask = 0xFFF.U(32.W)
    val currPageOffset = startAddr & pageMask
    val bytesToPageEnd = (4096.U - currPageOffset) & pageMask
    val maxBeatInPage = bytesToPageEnd / beatBytes.U
    val maxBeatByRemain = remainingBytes / beatBytes.U
    Mux(maxBeatInPage > 0.U, Mux(maxBeatInPage < maxBeatByRemain, maxBeatInPage, maxBeatByRemain), 1.U)
  }

  def alignTo32Byte(addr: UInt): UInt = (addr >> 5) << 5
}

// ==================== 核心DMA控制器（Chisel 7.0） ====================
class DMAController(
  fifoDepth: Int = 64,          // FIFO深度（64*32B=2048B）
  burstBeatBytes: Int = 32,     // 每beat 32字节
  maxBurstLen: Int = 8          // 最大Burst长度（8beat=256B）
) extends Module {
  val io = IO(new Bundle {
    val apb = new APB4IO()       // APB配置接口
    val axi = new AXI4Intf()     // AXI4 Master接口
    val dma_busy = Output(Bool())// 忙状态
    val fifo_level = Output(UInt(8.W)) // FIFO水位
  })

  // -------------------- 1. Chisel 7.0枚举（用法不变，仍在chisel3.util） --------------------
  // Chisel-style Enum (returns UInt states)
  val sIdle :: sReadBurstSetup :: sReadData :: sWriteBurstSetup :: sWriteData :: sDone :: Nil = Enum(6)
  val stateReg = RegInit(sIdle)

  // -------------------- 2. 配置寄存器 --------------------
  val regSrcAddr  = RegInit(0.U(32.W))
  val regDstAddr  = RegInit(0.U(32.W))
  val regLength   = RegInit(0.U(32.W))
  val regCtrl     = RegInit(0.U(32.W))  // bit0=启动, bit1=完成, bit2=错误
  val regStatus   = RegInit(0.U(32.W))  // bit0=忙, bit1=FIFO高水位

  // -------------------- 3. APB接口逻辑 --------------------
  val apbRegSel = Wire(UInt(4.W))
  apbRegSel := io.apb.PADDR(5, 2)  // 4字节对齐

  // APB默认值
  io.apb.PREADY := true.B
  io.apb.PSLVERR := false.B
  io.apb.PRDATA := 0.U

  // APB读操作
  when(io.apb.PSEL && !io.apb.PWRITE && io.apb.PENABLE) {
    switch(apbRegSel) {
      is(DmaRegs.SRC_ADDR_SEL)  { io.apb.PRDATA := regSrcAddr }
      is(DmaRegs.DST_ADDR_SEL)  { io.apb.PRDATA := regDstAddr }
      is(DmaRegs.LENGTH_SEL)    { io.apb.PRDATA := regLength }
      is(DmaRegs.CTRL_SEL)      { io.apb.PRDATA := regCtrl }
      is(DmaRegs.STATUS_SEL)    { io.apb.PRDATA := regStatus }
    }
  }

  // APB写操作（忙状态写保护）
  when(io.apb.PSEL && io.apb.PWRITE && io.apb.PENABLE && !regStatus(0)) {
    switch(apbRegSel) {
      is(DmaRegs.SRC_ADDR_SEL)  { regSrcAddr := io.apb.PWDATA }
      is(DmaRegs.DST_ADDR_SEL)  { regDstAddr := io.apb.PWDATA }
      is(DmaRegs.LENGTH_SEL)    { regLength := io.apb.PWDATA }
      is(DmaRegs.CTRL_SEL)      {
        // 写入控制寄存器，同时清除自动置位的完成/错误位 (bits 1 and 2)
        val clearMask = ~((1.U << 1) | (1.U << 2))
        regCtrl := io.apb.PWDATA & clearMask
      }
    }
  }

  // -------------------- 4. FIFO实例化（使用 Queue） --------------------
  val dataFifo = Module(new Queue(UInt(256.W), fifoDepth))
  
  // 兼容所有Chisel版本的FIFO计数方案（替代原非法的ram访问）
  val fifoCount = RegInit(0.U(log2Ceil(fifoDepth + 1).W))
  when(dataFifo.io.enq.fire) { fifoCount := fifoCount + 1.U }
  .elsewhen(dataFifo.io.deq.fire) { fifoCount := fifoCount - 1.U }
  io.fifo_level := fifoCount
  
  // 更新 regStatus bit1 (FIFO高水位)
  val fifoHighBit = (fifoCount >= maxBurstLen.U).asUInt << 1
  regStatus := (regStatus & ~(1.U << 1)) | fifoHighBit

  // -------------------- 5. 状态机变量 --------------------
  val remainingBytes = RegInit(0.U(32.W))
  val currSrcAddr = RegInit(0.U(32.W))
  val currDstAddr = RegInit(0.U(32.W))
  val currBurstLen = RegInit(0.U(8.W))

  // -------------------- 6. AXI默认值 --------------------
  // 读地址通道
  io.axi.ar.araddr := 0.U
  io.axi.ar.arburst := 1.U  // INCR
  io.axi.ar.arsize := 5.U   // 256bit=32字节
  io.axi.ar.arlen := 0.U
  io.axi.ar.arvalid := false.B
  io.axi.r.rready := true.B

  // 写地址通道
  io.axi.aw.awaddr := 0.U
  io.axi.aw.awburst := 1.U
  io.axi.aw.awsize := 5.U
  io.axi.aw.awlen := 0.U
  io.axi.aw.awvalid := false.B

  // 写数据通道
  io.axi.w.wdata := 0.U
  io.axi.w.wstrb := Fill(32, 1.U(1.W))
  io.axi.w.wlast := false.B
  io.axi.w.wvalid := false.B
  io.axi.b.bready := true.B

  // FIFO连接（SyncFIFO接口兼容）
  dataFifo.io.enq.bits := io.axi.r.rdata
  dataFifo.io.enq.valid := io.axi.r.rvalid
  dataFifo.io.deq.ready := false.B

  // -------------------- 7. DMA状态机逻辑 --------------------
  switch(stateReg) {
    is(sIdle) {
      when(regCtrl(0) && !regStatus(0)) {
        // 启动DMA
        remainingBytes := regLength
        currSrcAddr := regSrcAddr
        currDstAddr := regDstAddr
        // 置位 busy bit (bit 0)
        regStatus := regStatus | 1.U
        stateReg := sReadBurstSetup
      }
    }

    is(sReadBurstSetup) {
      when(remainingBytes > 0.U) {
        // 计算安全Burst长度
        val safeBurstLen = DmaUtils.getSafeBurstLen(currSrcAddr, remainingBytes, burstBeatBytes)
        currBurstLen := Mux(safeBurstLen > maxBurstLen.U, maxBurstLen.U, safeBurstLen)

        // 发送读地址
        io.axi.ar.araddr := currSrcAddr
        io.axi.ar.arlen := currBurstLen - 1.U
        io.axi.ar.arvalid := true.B

        when(io.axi.ar.arready) {
          io.axi.ar.arvalid := false.B
          stateReg := sReadData
        }
      } .otherwise {
        stateReg := sWriteBurstSetup
      }
    }

    is(sReadData) {
      when(io.axi.r.rvalid && dataFifo.io.enq.ready) {
        // 数据写入FIFO
        remainingBytes := remainingBytes - burstBeatBytes.U
        currSrcAddr := DmaUtils.alignTo32Byte(currSrcAddr + burstBeatBytes.U)

        // Burst结束判断
        when(io.axi.r.rlast || remainingBytes <= burstBeatBytes.U) {
          stateReg := Mux(remainingBytes > 0.U, sReadBurstSetup, sWriteBurstSetup)
        }
      }
    }

    is(sWriteBurstSetup) {
      when(fifoCount >= maxBurstLen.U) {
        // FIFO高水位，启动写Burst
        val safeBurstLen = DmaUtils.getSafeBurstLen(currDstAddr, remainingBytes, burstBeatBytes)
        val writeBurstLen = Mux(safeBurstLen > maxBurstLen.U, maxBurstLen.U, safeBurstLen)

        // 发送写地址
        io.axi.aw.awaddr := currDstAddr
        io.axi.aw.awlen := writeBurstLen - 1.U
        io.axi.aw.awvalid := true.B

        when(io.axi.aw.awready) {
          io.axi.aw.awvalid := false.B
          currBurstLen := writeBurstLen
          stateReg := sWriteData
        }
      }
    }

    is(sWriteData) {
      dataFifo.io.deq.ready := true.B
      when(dataFifo.io.deq.valid) {
        io.axi.w.wdata := dataFifo.io.deq.bits
        io.axi.w.wvalid := true.B
        io.axi.w.wlast := (currBurstLen === 1.U)

        when(io.axi.w.wready) {
          currBurstLen := currBurstLen - 1.U
          currDstAddr := DmaUtils.alignTo32Byte(currDstAddr + burstBeatBytes.U)

          when(io.axi.w.wlast) {
            stateReg := Mux(remainingBytes > 0.U || fifoCount > 0.U,
              sWriteBurstSetup, sDone)
          }
        }
      }
    }

    is(sDone) {
      // 设置完成位 (bit 1) and clear busy bit (bit 0)
      regCtrl := regCtrl | (1.U << 1)
      regStatus := regStatus & ~(1.U)
      stateReg := sIdle
    }
  }

  // -------------------- 8. 错误处理 --------------------
  when(io.axi.b.bresp =/= 0.U || (io.axi.r.rvalid && io.axi.r.rresp =/= 0.U)) {
    // 设置错误位 (bit 2) and clear busy bit
    regCtrl := regCtrl | (1.U << 2)
    regStatus := regStatus & ~(1.U)
    stateReg := sIdle
  }

  // -------------------- 9. 输出信号 --------------------
  io.dma_busy := regStatus(0)
}