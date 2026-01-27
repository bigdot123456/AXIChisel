package dmaAXI

import chisel3._
import chisel3.util._

// ==================== AXI4接口定义（适配Chisel 7.0） ====================
class AXI4WrAddrChannel(addrWidth: Int) extends Bundle {
  val awaddr  = UInt(addrWidth.W)
  val awburst = UInt(2.W)  // 00=FIXED, 01=INCR, 10=WRAP
  val awlen   = UInt(4.W)  // AXI4标准4bit (0=1beat, 15=16beats)
  val awsize  = UInt(3.W)  // 5=256bit
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
  val arlen   = UInt(4.W)
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

class AXI4Intf(addrWidth: Int = 32, dataWidth: Int = 256) extends Bundle {
  val aw = new AXI4WrAddrChannel(addrWidth)
  val w  = new AXI4WrDataChannel(dataWidth)
  val b  = new AXI4WrRespChannel()
  val ar = new AXI4RdAddrChannel(addrWidth)
  val r  = new AXI4RdDataChannel(dataWidth)
}

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
  val SRC_ADDR   = 0x00  // 源地址
  val DST_ADDR   = 0x04  // 目的地址
  val LENGTH     = 0x08  // 总长度（字节）
  val CTRL       = 0x0C  // bit0=启动, bit1=完成, bit2=错误
  val STATUS     = 0x10  // bit0=全局忙, bit1=FIFO高水位, bit2=读忙, bit3=写忙

  // APB地址解码（4字节对齐）
  val SRC_ADDR_SEL = (SRC_ADDR).U(32.W)(5, 2)
  val DST_ADDR_SEL = (DST_ADDR).U(32.W)(5, 2)
  val LENGTH_SEL   = (LENGTH).U(32.W)(5, 2)
  val CTRL_SEL     = (CTRL).U(32.W)(5, 2)
  val STATUS_SEL   = (STATUS).U(32.W)(5, 2)
}

// ==================== 4K边界检查工具 ====================
object DmaUtils {
  /**
   * 计算安全的Burst长度（不跨4K页）
   * @param startAddr 起始地址
   * @param remaining 剩余字节数
   * @param beatBytes 每beat字节数（默认32）
   * @return 安全Burst长度（AXI4标准0~15）
   */
  def getSafeBurstLen(startAddr: UInt, remaining: UInt, beatBytes: Int = 32): UInt = {
    val pageMask = 0xFFF.U(32.W)
    val offset = startAddr & pageMask
    val bytesToPageEnd = Mux(offset === 0.U, 4096.U, (4096.U - offset) & pageMask)
    
    val maxInPage = bytesToPageEnd / beatBytes.U
    val maxByRemain = remaining / beatBytes.U
    val safeLen = Mux(maxInPage > 0.U, Mux(maxInPage < maxByRemain, maxInPage, maxByRemain), 1.U)
    
    // 限制AXI4最大Burst长度（16beats）
    Mux(safeLen > 15.U, 15.U, safeLen)
  }

  // 32字节对齐
  def alignTo32Byte(addr: UInt): UInt = (addr >> 5) << 5
}

// ==================== 流水线控制信号 ====================
class PipelineCtrl extends Bundle {
  val read_enable  = Bool()  // 读阶段使能
  val write_enable = Bool()  // 写阶段使能
  val read_done    = Bool()  // 读完成
  val write_done   = Bool()  // 写完成
  val fifo_afull   = Bool()  // FIFO接近满（动态高水位）
  val fifo_empty   = Bool()  // FIFO空
}

// ==================== 核心流水线DMA控制器（中等成本优化版） ====================
class DMAController(
  totalFifoDepth: Int = 64,      // 总FIFO深度（64*32B=2048B）
  burstBeatBytes: Int = 32,      // 每beat 32字节
  maxBurstLen: Int = 15          // AXI4最大Burst长度（16beats）
) extends Module {
  val io = IO(new Bundle {
    val apb  = new APB4IO()      // APB配置接口
    val axi  = new AXI4Intf()    // AXI4 Master接口
    val busy = Output(Bool())    // DMA忙状态
    val level = Output(UInt(8.W))// FIFO总水位
  })

  // -------------------- 1. 全局配置与状态 --------------------
  // 全局状态机（仅控制启停/错误）
  val sIdle :: sRunning :: sDone :: sError :: Nil = Enum(4)
  val globalState = RegInit(sIdle)

  // 配置寄存器
  val regSrcAddr  = RegInit(0.U(32.W))
  val regDstAddr  = RegInit(0.U(32.W))
  val regTotalLen = RegInit(0.U(32.W))
  val regCtrl     = RegInit(0.U(32.W))
  val regStatus   = RegInit(0.U(32.W))

  // 剩余字节计数器（读/写共享，原子更新）
  val remainBytes = RegInit(0.U(32.W))
  val remainRead  = Wire(UInt(32.W))
  val remainWrite = Wire(UInt(32.W))
  remainRead  := remainBytes
  remainWrite := remainBytes

  // -------------------- 2. APB接口逻辑 --------------------
  val apbSel = Wire(UInt(4.W))
  apbSel := io.apb.PADDR(5, 2)

  // APB默认值（避免未初始化）
  io.apb.PREADY  := true.B
  io.apb.PSLVERR := false.B
  io.apb.PRDATA  := 0.U

  // APB读操作
  when(io.apb.PSEL && !io.apb.PWRITE && io.apb.PENABLE) {
    switch(apbSel) {
      is(DmaRegs.SRC_ADDR_SEL)  { io.apb.PRDATA := regSrcAddr }
      is(DmaRegs.DST_ADDR_SEL)  { io.apb.PRDATA := regDstAddr }
      is(DmaRegs.LENGTH_SEL)    { io.apb.PRDATA := regTotalLen }
      is(DmaRegs.CTRL_SEL)      { io.apb.PRDATA := regCtrl }
      is(DmaRegs.STATUS_SEL)    { io.apb.PRDATA := regStatus }
    }
  }

  // APB写操作（忙状态写保护）
  when(io.apb.PSEL && io.apb.PWRITE && io.apb.PENABLE && !regStatus(0)) {
    switch(apbSel) {
      is(DmaRegs.SRC_ADDR_SEL)  { regSrcAddr := io.apb.PWDATA }
      is(DmaRegs.DST_ADDR_SEL)  { regDstAddr := io.apb.PWDATA }
      is(DmaRegs.LENGTH_SEL)    { regTotalLen := io.apb.PWDATA }
      is(DmaRegs.CTRL_SEL)      {
        val clearMask = ~((1.U << 1) | (1.U << 2))  // 清除完成/错误位
        regCtrl := io.apb.PWDATA & clearMask
      }
    }
  }

  // -------------------- 3. 双FIFO乒乓缓存（核心优化1） --------------------
  val fifoDepth = totalFifoDepth / 2  // 每个FIFO深度32
  val fifoA = Module(new Queue(UInt(256.W), fifoDepth, pipe = true))
  val fifoB = Module(new Queue(UInt(256.W), fifoDepth, pipe = true))
  
  // FIFO默认值（避免未初始化）
  fifoA.io.enq.valid := false.B
  fifoA.io.enq.bits  := 0.U
  fifoA.io.deq.ready := false.B
  fifoB.io.enq.valid := false.B
  fifoB.io.enq.bits  := 0.U
  fifoB.io.deq.ready := false.B

  // 乒乓切换控制
  val writeFifoSel = RegInit(true.B)  // true=写FIFO A，false=写FIFO B
  val readFifoSel = RegInit(false.B)  // true=读FIFO A，false=读FIFO B（与写相反）
  
  // 总FIFO水位
  val fifoASize = fifoA.io.count
  val fifoBSize = fifoB.io.count
  val totalFifoLevel = fifoASize + fifoBSize
  io.level := totalFifoLevel

  // -------------------- 4. 动态水位控制（核心优化2） --------------------
  // 统计AXI响应速率（0=最慢，3=最快）
  val readRespRate = RegInit(1.U(2.W))
  val writeRespRate = RegInit(1.U(2.W))
  
  // 读响应速率统计：连续rvalid表示速率快
  when(io.axi.r.rvalid && io.axi.r.rready) {
    readRespRate := Mux(readRespRate < 3.U, readRespRate + 1.U, 3.U)
  }.otherwise {
    readRespRate := Mux(readRespRate > 0.U, readRespRate - 1.U, 0.U)
  }
  
  // 动态高水位计算（根据读响应速率调整）
  val dynamicHighWater = MuxCase(
    (fifoDepth * 3 / 4).U,  // 默认75%
    Seq(
      (readRespRate === 0.U) -> (fifoDepth * 1 / 2).U,  // 读慢→50%高水位
      (readRespRate === 1.U) -> (fifoDepth * 2 / 3).U,  // 读较慢→66%高水位
      (readRespRate === 3.U) -> (fifoDepth * 4 / 5).U   // 读快→80%高水位
    )
  )
  
  // -------------------- 5. 流水线控制信号生成 --------------------
  val pipeCtrl = Wire(new PipelineCtrl)
  // 分别判断当前写FIFO的水位（修复：避免Mux选择后赋值）
  val currWriteFifoAFull = writeFifoSel && (fifoASize >= dynamicHighWater)
  val currWriteFifoBFull = !writeFifoSel && (fifoBSize >= dynamicHighWater)
  val currReadFifoEmpty = Mux(readFifoSel, (fifoASize === 0.U), (fifoBSize === 0.U))
  
  pipeCtrl.read_enable  := (globalState === sRunning) && !pipeCtrl.read_done && !currWriteFifoAFull && !currWriteFifoBFull
  pipeCtrl.write_enable := (globalState === sRunning) && !pipeCtrl.write_done && !currReadFifoEmpty
  pipeCtrl.read_done    := (remainRead === 0.U)
  pipeCtrl.write_done   := (remainWrite === 0.U) && (totalFifoLevel === 0.U)
  pipeCtrl.fifo_afull   := currWriteFifoAFull || currWriteFifoBFull
  pipeCtrl.fifo_empty   := (totalFifoLevel === 0.U)

  // 更新状态寄存器
  regStatus := Cat(
    pipeCtrl.write_enable,  // bit3: 写忙
    pipeCtrl.read_enable,   // bit2: 读忙
    pipeCtrl.fifo_afull,    // bit1: FIFO高水位
    (globalState === sRunning) // bit0: 全局忙
  )

  // -------------------- 6. 读流水线 + Burst预取（核心优化3） --------------------
  // 读阶段状态机
  val sRIdle :: sRSetup :: sRData :: Nil = Enum(3)
  val readState = RegInit(sRIdle)
  
  // 读阶段寄存器
  val readAddr   = RegInit(0.U(32.W))
  val readBurst  = RegInit(0.U(4.W))
  val readBeatCnt = RegInit(0.U(4.W))
  
  // Burst预取寄存器（核心优化）
  val nextReadAddr = RegInit(0.U(32.W))  // 预存下一个Burst地址
  val nextReadBurst = RegInit(0.U(4.W))  // 预存下一个Burst长度
  val prefetchReady = RegInit(false.B)   // 预取完成标志

  // AXI读通道默认值
  io.axi.ar.araddr  := 0.U
  io.axi.ar.arburst := 1.U  // INCR
  io.axi.ar.arsize  := 5.U  // 256bit
  io.axi.ar.arlen   := 0.U
  io.axi.ar.arvalid := false.B
  io.axi.r.rready   := false.B

  // 读FIFO驱动信号（修复核心：定义临时信号，避免直接赋值Mux选择的接口）
  val fifoAWriteEn = Wire(Bool())
  val fifoBWriteEn = Wire(Bool())
  val fifoWriteData = Wire(UInt(256.W))
  fifoAWriteEn := false.B
  fifoBWriteEn := false.B
  fifoWriteData := 0.U

  // 读状态机逻辑
  switch(readState) {
    is(sRIdle) {
      when(pipeCtrl.read_enable) {
        readAddr := Mux(readAddr === 0.U, regSrcAddr, readAddr)
        readState := sRSetup
        prefetchReady := false.B // 重置预取标志
      }
    }

    is(sRSetup) {
      // 计算当前Burst长度
      val safeLen = DmaUtils.getSafeBurstLen(readAddr, remainRead, burstBeatBytes)
      readBurst := Mux(safeLen > maxBurstLen.U, maxBurstLen.U, safeLen)
      
      // 发送当前Burst地址
      io.axi.ar.araddr  := readAddr
      io.axi.ar.arlen   := readBurst - 1.U
      io.axi.ar.arvalid := true.B

      when(io.axi.ar.arready) {
        io.axi.ar.arvalid := false.B
        readBeatCnt := 0.U
        readState := sRData
        io.axi.r.rready := true.B  // Always Ready优化
        
        // 预计算下一个Burst（核心优化）
        val nextAddr = DmaUtils.alignTo32Byte(readAddr + readBurst * burstBeatBytes.U)
        val nextRemain = remainRead - readBurst * burstBeatBytes.U
        nextReadAddr := nextAddr
        nextReadBurst := DmaUtils.getSafeBurstLen(nextAddr, nextRemain, burstBeatBytes)
        prefetchReady := true.B // 预取完成
      }
    }

    is(sRData) {
      io.axi.r.rready := true.B // Always Ready优化（减少间隙）
      
      // 数据写入FIFO（修复：根据writeFifoSel分别驱动fifoA/fifoB，而非Mux选择后赋值）
      when(io.axi.r.rvalid) {
        fifoWriteData := io.axi.r.rdata
        // 根据乒乓选择驱动对应FIFO
        when(writeFifoSel && fifoA.io.enq.ready) {
          fifoAWriteEn := true.B
        }.elsewhen(!writeFifoSel && fifoB.io.enq.ready) {
          fifoBWriteEn := true.B
        }
        
        // 更新计数器和地址
        readBeatCnt := readBeatCnt + 1.U
        remainBytes := remainBytes - burstBeatBytes.U
        readAddr := DmaUtils.alignTo32Byte(readAddr + burstBeatBytes.U)

        // Burst预取：当前Burst传输到一半时，提前发送下一个地址（核心优化）
        when((readBeatCnt === (readBurst / 2.U)) && prefetchReady && pipeCtrl.read_enable) {
          io.axi.ar.araddr := nextReadAddr
          io.axi.ar.arlen := nextReadBurst - 1.U
          io.axi.ar.arvalid := true.B // 提前发送地址，隐藏握手延迟
        }

        // Burst结束判断
        val burstEnd = io.axi.r.rlast || (readBeatCnt === readBurst) || pipeCtrl.read_done
        when(burstEnd) {
          io.axi.r.rready := false.B
          
          // 乒乓切换：当前写FIFO满时切换
          when((writeFifoSel && (fifoASize >= dynamicHighWater)) || (!writeFifoSel && (fifoBSize >= dynamicHighWater))) {
            writeFifoSel := !writeFifoSel
            readFifoSel := !readFifoSel
          }
          
          // 预取命中：直接使用预取的Burst，跳过Setup阶段
          when(prefetchReady && pipeCtrl.read_enable) {
            readAddr := nextReadAddr
            readBurst := nextReadBurst
            readBeatCnt := 0.U
            prefetchReady := false.B
            readState := sRData // 跳过Setup，直接继续读
          }.otherwise {
            readState := Mux(pipeCtrl.read_enable, sRSetup, sRIdle)
          }
        }
      }
    }
  }

  // 驱动FIFO写使能（最终赋值，避免只读接口错误）
  fifoA.io.enq.valid := fifoAWriteEn
  fifoA.io.enq.bits := fifoWriteData
  fifoB.io.enq.valid := fifoBWriteEn
  fifoB.io.enq.bits := fifoWriteData

  // -------------------- 7. 写流水线 --------------------
  // 写阶段状态机
  val sWIdle :: sWSetup :: sWData :: Nil = Enum(3)
  val writeState = RegInit(sWIdle)
  
  // 写阶段寄存器
  val writeAddr   = RegInit(0.U(32.W))
  val writeBurst  = RegInit(0.U(4.W))
  val writeBeatCnt = RegInit(0.U(4.W))

  // AXI写通道默认值
  io.axi.aw.awaddr  := 0.U
  io.axi.aw.awburst := 1.U  // 修正后的正确字段
  io.axi.aw.awsize  := 5.U
  io.axi.aw.awlen   := 0.U
  io.axi.aw.awvalid := false.B
  
  io.axi.w.wdata  := 0.U
  io.axi.w.wstrb  := Fill(32, 1.U(1.W))
  io.axi.w.wlast  := false.B
  io.axi.w.wvalid := false.B
  io.axi.b.bready := true.B

  // 写FIFO读使能（修复：分别驱动fifoA/fifoB的deq.ready）
  val fifoAReadEn = Wire(Bool())
  val fifoBReadEn = Wire(Bool())
  fifoAReadEn := false.B
  fifoBReadEn := false.B

  // 写状态机逻辑
  switch(writeState) {
    is(sWIdle) {
      when(pipeCtrl.write_enable) {
        writeAddr := Mux(writeAddr === 0.U, regDstAddr, writeAddr)
        writeState := sWSetup
      }
    }

    is(sWSetup) {
      // 计算安全Burst长度
      val safeLen = DmaUtils.getSafeBurstLen(writeAddr, remainWrite, burstBeatBytes)
      writeBurst := Mux(safeLen > maxBurstLen.U, maxBurstLen.U, safeLen)
      
      // 发送写地址
      io.axi.aw.awaddr  := writeAddr
      io.axi.aw.awlen   := writeBurst - 1.U
      io.axi.aw.awvalid := true.B

      when(io.axi.aw.awready) {
        io.axi.aw.awvalid := false.B
        writeBeatCnt := 0.U
        writeState := sWData
      }
    }

    is(sWData) {
      // 根据乒乓选择驱动对应FIFO的读使能（修复核心）
      when(readFifoSel) {
        fifoAReadEn := true.B
        when(fifoA.io.deq.valid) {
          io.axi.w.wdata  := fifoA.io.deq.bits
          io.axi.w.wvalid := true.B
        }
      }.otherwise {
        fifoBReadEn := true.B
        when(fifoB.io.deq.valid) {
          io.axi.w.wdata  := fifoB.io.deq.bits
          io.axi.w.wvalid := true.B
        }
      }
      io.axi.w.wlast  := (writeBeatCnt === writeBurst - 1.U)

      when(io.axi.w.wready && (fifoA.io.deq.valid || fifoB.io.deq.valid)) {
        writeBeatCnt := writeBeatCnt + 1.U
        writeAddr := DmaUtils.alignTo32Byte(writeAddr + burstBeatBytes.U)

        // Burst结束判断
        val burstEnd = io.axi.w.wlast || pipeCtrl.write_done
        when(burstEnd) {
          fifoAReadEn := false.B
          fifoBReadEn := false.B
          
          // 乒乓切换：当前读FIFO空时切换
          when((readFifoSel && (fifoASize === 0.U)) || (!readFifoSel && (fifoBSize === 0.U))) {
            readFifoSel := !readFifoSel
            writeFifoSel := !writeFifoSel
          }
          
          writeState := Mux(pipeCtrl.write_enable, sWSetup, sWIdle)
        }
      }
    }
  }

  // 驱动FIFO读使能（最终赋值）
  fifoA.io.deq.ready := fifoAReadEn
  fifoB.io.deq.ready := fifoBReadEn

  // -------------------- 8. 全局状态机控制 --------------------
  switch(globalState) {
    is(sIdle) {
      when(regCtrl(0) && !regStatus(0)) {
        // 启动流水线，过滤零长度传输
        when(regTotalLen === 0.U) {
          regCtrl := regCtrl | (1.U << 1)  // 直接置位完成位
        }.otherwise {
          remainBytes := regTotalLen
          readAddr := regSrcAddr
          writeAddr := regDstAddr
          globalState := sRunning
        }
      }
    }

    is(sRunning) {
      // 检测完成/错误
      when(pipeCtrl.write_done) {
        regCtrl := regCtrl | (1.U << 1)  // 置位完成位
        globalState := sDone
      }.elsewhen((io.axi.b.bvalid && io.axi.b.bresp =/= 0.U) || (io.axi.r.rvalid && io.axi.r.rresp =/= 0.U)) {
        regCtrl := regCtrl | (1.U << 2)  // 置位错误位
        globalState := sError
      }
    }

    is(sDone) {
      // 完成：清除忙位，重置控制
      regCtrl := regCtrl & ~(1.U << 0)  // 清除启动位
      globalState := sIdle
    }

    is(sError) {
      // 错误：重置所有状态
      regCtrl := regCtrl & ~(1.U << 0)
      remainBytes := 0.U
      // 重置FIFO乒乓选择
      writeFifoSel := true.B
      readFifoSel := false.B
      // 重置FIFO驱动信号
      fifoAWriteEn := false.B
      fifoBWriteEn := false.B
      fifoAReadEn := false.B
      fifoBReadEn := false.B
      globalState := sIdle
    }
  }

  // -------------------- 9. 输出信号 --------------------
  io.busy := regStatus(0)
}
