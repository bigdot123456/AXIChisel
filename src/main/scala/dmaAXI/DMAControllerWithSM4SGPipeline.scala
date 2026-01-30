package dmaAXI

// 引入必要的Chisel库
import chisel3._
import chisel3.util._
import chisel3.experimental.BundleLiterals._

// ==================== 1. 全局常量定义（避免魔法数） ====================
object DmaSM4SGConfig {
  // 总线配置
  val AXI_ADDR_WIDTH = 32
  val AXI_DATA_WIDTH = 256  // 32字节burst
  val AXI_BURST_MAX_LEN = 15 // AXI4最大burst长度
  val BEAT_BYTES = 32        // 单次beat字节数
  
  // FIFO深度
  val READ_FIFO_DEPTH = 32
  val CRYPTO_FIFO_DEPTH = 32
  
  // 寄存器地址映射
  val REG_SRC_ADDR   = 0x00
  val REG_DST_ADDR   = 0x04
  val REG_LENGTH     = 0x08
  val REG_CTRL       = 0x0C
  val REG_STATUS     = 0x10
  val REG_SM4_KEY0   = 0x14
  val REG_SM4_KEY1   = 0x18
  val REG_SM4_KEY2   = 0x1C
  val REG_SM4_KEY3   = 0x20
  val REG_SM4_IV0    = 0x24
  val REG_SM4_IV1    = 0x28
  val REG_SM4_IV2    = 0x2C
  val REG_SM4_IV3    = 0x30
  val REG_SG_BASE    = 0x34  // SG描述符链表基地址
  val REG_SG_CURR    = 0x38  // 当前SG描述符地址（只读）
  val REG_SG_CTRL    = 0x3C  // SG模式控制寄存器
  val REG_SG_TOTAL   = 0x40  // SG总传输字节数（只读）
  
  // 控制位定义
  val CTRL_START     = 0  // 单块传输启动
  val CTRL_DONE      = 1  // 传输完成
  val CTRL_ERROR     = 2  // 传输错误
  val CTRL_CRYPTO_EN = 3  // 加解密使能
  val CTRL_CRYPTO_MODE = 5 // 0=加密,1=解密
  
  // SG控制位定义
  val SG_CTRL_EN     = 0  // SG模式使能
  val SG_CTRL_START  = 1  // SG传输启动
  val SG_CTRL_DONE   = 2  // SG传输完成
  val SG_CTRL_ERROR  = 3  // SG传输错误
  
  // 描述符控制位
  val DESC_CTRL_END  = 0  // 结束标志
  val DESC_CTRL_CRYPTO_EN = 1 // 该块加解密使能
  val DESC_CTRL_CRYPTO_MODE = 2 // 0=加密,1=解密
}

// ==================== 2. SG描述符定义（32字节对齐） ====================
class SGDescriptor extends Bundle {
  val src_addr  = UInt(DmaSM4SGConfig.AXI_ADDR_WIDTH.W)  // 源地址
  val dst_addr  = UInt(DmaSM4SGConfig.AXI_ADDR_WIDTH.W)  // 目的地址
  val length    = UInt(DmaSM4SGConfig.AXI_ADDR_WIDTH.W)  // 传输长度
  val ctrl      = UInt(32.W)  // 控制位: bit0=结束标志, bit1=加解密使能, bit2=加解密模式
  val reserved  = UInt(128.W) // 保留字段，凑32字节
}

// ==================== 3. 接口定义 ====================
// APB4从接口
class APB4SlaveIO extends Bundle {
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

// AXI4主接口（简化版，只保留必要信号）
class AXI4MasterIO extends Bundle {
  // 读地址通道
  val araddr  = Output(UInt(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val arburst = Output(UInt(2.W))  // 0=固定,1=增量,2=回绕
  val arsize  = Output(UInt(3.W))  // 数据宽度: 5=32字节
  val arlen   = Output(UInt(8.W))  // burst长度
  val arvalid = Output(Bool())
  val arready = Input(Bool())
  
  // 读数据通道
  val rdata  = Input(UInt(DmaSM4SGConfig.AXI_DATA_WIDTH.W))
  val rresp  = Input(UInt(2.W))    // 响应: 0=OKAY
  val rlast  = Input(Bool())
  val rvalid = Input(Bool())
  val rready = Output(Bool())
  
  // 写地址通道
  val awaddr  = Output(UInt(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val awburst = Output(UInt(2.W))
  val awsize  = Output(UInt(3.W))
  val awlen   = Output(UInt(8.W))
  val awvalid = Output(Bool())
  val awready = Input(Bool())
  
  // 写数据通道
  val wdata  = Output(UInt(DmaSM4SGConfig.AXI_DATA_WIDTH.W))
  val wstrb  = Output(UInt(DmaSM4SGConfig.BEAT_BYTES.W)) // 字节选通
  val wlast  = Output(Bool())
  val wvalid = Output(Bool())
  val wready = Input(Bool())
  
  // 写响应通道
  val bresp  = Input(UInt(2.W))
  val bvalid = Input(Bool())
  val bready = Output(Bool())
}

// ==================== 4. SM4加解密模块（4周期流水线） ====================
class SM4Pipeline extends Module {
  val io = IO(new Bundle {
    val en        = Input(Bool())          // 使能
    val reset_iv  = Input(Bool())          // 重置IV
    val mode      = Input(Bool())          // 0=加密,1=解密
    val key       = Input(Vec(4, UInt(32.W))) // 128位密钥
    val init_iv   = Input(Vec(4, UInt(32.W))) // 初始IV
    val plaintext = Input(UInt(128.W))     // 明文输入
    val ciphertext = Output(UInt(128.W))   // 密文输出
    val valid     = Output(Bool())         // 输出有效
    val iv_out    = Output(Vec(4, UInt(32.W))) // IV输出
  })

  // SM4 S盒（国标）
  val SBOX = VecInit(
    0xd6.U(8.W), 0x90.U(8.W), 0xe9.U(8.W), 0xfe.U(8.W), 0xcc.U(8.W), 0xe1.U(8.W), 0x3d.U(8.W), 0xb7.U(8.W),
    0x16.U(8.W), 0xb6.U(8.W), 0x14.U(8.W), 0xc2.U(8.W), 0x28.U(8.W), 0xfb.U(8.W), 0x2c.U(8.W), 0x05.U(8.W),
    0x2b.U(8.W), 0x67.U(8.W), 0x9a.U(8.W), 0x76.U(8.W), 0x2a.U(8.W), 0xbe.U(8.W), 0x04.U(8.W), 0xc3.U(8.W),
    0xaa.U(8.W), 0x44.U(8.W), 0x13.U(8.W), 0x26.U(8.W), 0x49.U(8.W), 0x86.U(8.W), 0x06.U(8.W), 0x99.U(8.W),
    0x9c.U(8.W), 0x42.U(8.W), 0x50.U(8.W), 0xf4.U(8.W), 0x91.U(8.W), 0xef.U(8.W), 0x98.U(8.W), 0x7a.U(8.W),
    0x33.U(8.W), 0x54.U(8.W), 0x0b.U(8.W), 0x43.U(8.W), 0xed.U(8.W), 0xcf.U(8.W), 0xac.U(8.W), 0x62.U(8.W),
    0xe4.U(8.W), 0xb3.U(8.W), 0x1c.U(8.W), 0xa9.U(8.W), 0xc9.U(8.W), 0x08.U(8.W), 0xe8.U(8.W), 0x95.U(8.W),
    0x80.U(8.W), 0xdf.U(8.W), 0x94.U(8.W), 0xfa.U(8.W), 0x75.U(8.W), 0x8f.U(8.W), 0x3f.U(8.W), 0xa6.U(8.W),
    0x47.U(8.W), 0x07.U(8.W), 0xa7.U(8.W), 0xfc.U(8.W), 0xf3.U(8.W), 0x73.U(8.W), 0x17.U(8.W), 0xba.U(8.W),
    0x83.U(8.W), 0x59.U(8.W), 0x3c.U(8.W), 0x19.U(8.W), 0xe6.U(8.W), 0x85.U(8.W), 0x4f.U(8.W), 0xa8.U(8.W),
    0x68.U(8.W), 0x6b.U(8.W), 0x81.U(8.W), 0xb2.U(8.W), 0x71.U(8.W), 0x64.U(8.W), 0xda.U(8.W), 0x8b.U(8.W),
    0xf8.U(8.W), 0xeb.U(8.W), 0x0f.U(8.W), 0x4b.U(8.W), 0x70.U(8.W), 0x56.U(8.W), 0x9d.U(8.W), 0x35.U(8.W),
    0x1e.U(8.W), 0x24.U(8.W), 0x0e.U(8.W), 0x5e.U(8.W), 0x63.U(8.W), 0x58.U(8.W), 0xd1.U(8.W), 0xa2.U(8.W),
    0x25.U(8.W), 0x22.U(8.W), 0x7c.U(8.W), 0x3b.U(8.W), 0x01.U(8.W), 0x21.U(8.W), 0x78.U(8.W), 0x87.U(8.W),
    0xd4.U(8.W), 0x00.U(8.W), 0x46.U(8.W), 0x57.U(8.W), 0x9f.U(8.W), 0xd3.U(8.W), 0x27.U(8.W), 0x52.U(8.W),
    0x4c.U(8.W), 0x36.U(8.W), 0x02.U(8.W), 0xe7.U(8.W), 0xa0.U(8.W), 0xc4.U(8.W), 0xc8.U(8.W), 0x9e.U(8.W),
    0xea.U(8.W), 0xbf.U(8.W), 0x8a.U(8.W), 0xd2.U(8.W), 0x40.U(8.W), 0xc7.U(8.W), 0x38.U(8.W), 0xb5.U(8.W),
    0xa3.U(8.W), 0xf7.U(8.W), 0xf2.U(8.W), 0xce.U(8.W), 0xf9.U(8.W), 0x61.U(8.W), 0x15.U(8.W), 0xa1.U(8.W),
    0xe0.U(8.W), 0xae.U(8.W), 0x5d.U(8.W), 0xa4.U(8.W), 0x9b.U(8.W), 0x34.U(8.W), 0x1a.U(8.W), 0x55.U(8.W),
    0xad.U(8.W), 0x93.U(8.W), 0x32.U(8.W), 0x30.U(8.W), 0xf5.U(8.W), 0x8c.U(8.W), 0xb1.U(8.W), 0xe3.U(8.W),
    0x1d.U(8.W), 0xf6.U(8.W), 0xe2.U(8.W), 0x2e.U(8.W), 0x82.U(8.W), 0x66.U(8.W), 0xca.U(8.W), 0x60.U(8.W),
    0xc0.U(8.W), 0x29.U(8.W), 0x23.U(8.W), 0xab.U(8.W), 0x0d.U(8.W), 0x53.U(8.W), 0x4e.U(8.W), 0x6f.U(8.W),
    0xd5.U(8.W), 0xdb.U(8.W), 0x37.U(8.W), 0x45.U(8.W), 0xde.U(8.W), 0xfd.U(8.W), 0x8e.U(8.W), 0x2f.U(8.W),
    0x03.U(8.W), 0xff.U(8.W), 0x6a.U(8.W), 0x72.U(8.W), 0x6d.U(8.W), 0x6c.U(8.W), 0x5b.U(8.W), 0x51.U(8.W),
    0x8d.U(8.W), 0x1b.U(8.W), 0xaf.U(8.W), 0x92.U(8.W), 0xbb.U(8.W), 0xdd.U(8.W), 0xbc.U(8.W), 0x7f.U(8.W),
    0x11.U(8.W), 0xd9.U(8.W), 0x5c.U(8.W), 0x41.U(8.W), 0x1f.U(8.W), 0x10.U(8.W), 0x5a.U(8.W), 0xd8.U(8.W),
    0x0a.U(8.W), 0xc1.U(8.W), 0x31.U(8.W), 0x88.U(8.W), 0xa5.U(8.W), 0xcd.U(8.W), 0x7b.U(8.W), 0xbd.U(8.W),
    0x2d.U(8.W), 0x74.U(8.W), 0xd0.U(8.W), 0x12.U(8.W), 0xb8.U(8.W), 0xe5.U(8.W), 0xb4.U(8.W), 0xb0.U(8.W),
    0x89.U(8.W), 0x69.U(8.W), 0x97.U(8.W), 0x4a.U(8.W), 0x0c.U(8.W), 0x96.U(8.W), 0x77.U(8.W), 0x7e.U(8.W),
    0x65.U(8.W), 0xb9.U(8.W), 0xf1.U(8.W), 0x09.U(8.W), 0xc5.U(8.W), 0x6e.U(8.W), 0xc6.U(8.W), 0x84.U(8.W),
    0x18.U(8.W), 0xf0.U(8.W), 0x7d.U(8.W), 0xec.U(8.W), 0x3a.U(8.W), 0xdc.U(8.W), 0x4d.U(8.W), 0x20.U(8.W),
    0x79.U(8.W), 0xee.U(8.W), 0x5f.U(8.W), 0x3e.U(8.W), 0xd7.U(8.W), 0xcb.U(8.W), 0x39.U(8.W), 0x48.U(8.W)
  )

  // 系统参数
  val FK = VecInit(
    BigInt("a3b1bac6", 16).U(32.W),
    BigInt("56aa3350", 16).U(32.W),
    BigInt("677d9197", 16).U(32.W),
    BigInt("b27022dc", 16).U(32.W)
  )

  val CK = VecInit(
    BigInt("00070e15",16).U(32.W), BigInt("1c232a31",16).U(32.W), BigInt("383f464d",16).U(32.W), BigInt("545b6269",16).U(32.W),
    BigInt("70777e85",16).U(32.W), BigInt("8c939aa1",16).U(32.W), BigInt("a8afb6bd",16).U(32.W), BigInt("c4cbd2d9",16).U(32.W),
    BigInt("e0e7eef5",16).U(32.W), BigInt("fc030a11",16).U(32.W), BigInt("181f262d",16).U(32.W), BigInt("343b4249",16).U(32.W),
    BigInt("50575e65",16).U(32.W), BigInt("6c737a81",16).U(32.W), BigInt("888f969d",16).U(32.W), BigInt("a4abb2b9",16).U(32.W),
    BigInt("c0c7ced5",16).U(32.W), BigInt("dce3eaf1",16).U(32.W), BigInt("f8ff060d",16).U(32.W), BigInt("141b2229",16).U(32.W),
    BigInt("30373e45",16).U(32.W), BigInt("4c535a61",16).U(32.W), BigInt("686f767d",16).U(32.W), BigInt("848b9299",16).U(32.W),
    BigInt("a0a7aeb5",16).U(32.W), BigInt("bcc3cad1",16).U(32.W), BigInt("d8dfe6ed",16).U(32.W), BigInt("f4fb0209",16).U(32.W),
    BigInt("10171e25",16).U(32.W), BigInt("2c333a41",16).U(32.W), BigInt("484f565d",16).U(32.W), BigInt("646b7279",16).U(32.W)
  )

  // S盒替换
  def sboxSub(in: UInt): UInt = {
    val bytes = VecInit((0 to 3).map(i => in(8*(3-i)+7, 8*(3-i))))
    VecInit(bytes.map(b => SBOX(b))).asUInt
  }

  // 循环左移
  def rotl(in: UInt, n: Int): UInt = (in << n) | (in >> (32 - n))

  // 线性变换
  def ltrans(in: UInt): UInt = in ^ rotl(in, 2) ^ rotl(in, 10) ^ rotl(in, 18) ^ rotl(in, 24)

  // T变换
  def ttrans(in: UInt): UInt = ltrans(sboxSub(in))

  // 密钥扩展
  def keyExp(in: UInt, ck: UInt): UInt = in ^ ttrans(in ^ rotl(in, 13) ^ rotl(in, 23) ^ ck)

  // 密钥扩展
  val rk = RegInit(VecInit(Seq.fill(32)(0.U(32.W))))
  val mk = VecInit((0 to 3).map(i => io.key(i) ^ FK(i)))
  
  rk(0) := keyExp(mk(1) ^ mk(2) ^ mk(3) ^ CK(0), CK(0))
  rk(1) := keyExp(mk(2) ^ mk(3) ^ rk(0) ^ CK(1), CK(1))
  rk(2) := keyExp(mk(3) ^ rk(0) ^ rk(1) ^ CK(2), CK(2))
  rk(3) := keyExp(rk(0) ^ rk(1) ^ rk(2) ^ CK(3), CK(3))
  
  for (i <- 4 until 32) {
    rk(i) := keyExp(rk(i-1) ^ rk(i-2) ^ rk(i-3) ^ CK(i), CK(i))
  }

  // 加密/解密密钥选择
  val rk_sel = VecInit((0 until 32).map(i => Mux(io.mode, rk(31 - i), rk(i))))

  // IV寄存器
  val iv_reg = RegInit(VecInit(Seq.fill(4)(0.U(32.W))))
  when(io.reset_iv) {
    iv_reg := io.init_iv
  }.elsewhen(io.en) {
    val iv_128 = Cat(iv_reg(3), iv_reg(2), iv_reg(1), iv_reg(0))
    val iv_inc = iv_128 + 1.U(128.W)
    iv_reg(0) := iv_inc(31, 0)
    iv_reg(1) := iv_inc(63, 32)
    iv_reg(2) := iv_inc(95, 64)
    iv_reg(3) := iv_inc(127, 96)
  }
  io.iv_out := iv_reg

  // 4周期流水线
  val pipe_x = RegInit(VecInit(Seq.fill(4)(VecInit(Seq.fill(4)(0.U(32.W))))))
  val pipe_valid = RegInit(VecInit(Seq.fill(5)(false.B)))

  // 流水线输入
  when(io.en) {
    pipe_x(0)(0) := io.plaintext(31, 0)
    pipe_x(0)(1) := io.plaintext(63, 32)
    pipe_x(0)(2) := io.plaintext(95, 64)
    pipe_x(0)(3) := io.plaintext(127, 96)
    pipe_valid(0) := true.B
  }.otherwise {
    pipe_valid(0) := false.B
  }

  // 流水线阶段1 (0-7轮)
  val x_stage1 = VecInit(Seq.fill(12)(0.U(32.W)))
  x_stage1(0) := pipe_x(0)(0)
  x_stage1(1) := pipe_x(0)(1)
  x_stage1(2) := pipe_x(0)(2)
  x_stage1(3) := pipe_x(0)(3)
  for (i <- 0 until 8) {
    x_stage1(i+4) := x_stage1(i) ^ ttrans(x_stage1(i+1) ^ x_stage1(i+2) ^ x_stage1(i+3) ^ rk_sel(i))
  }
  pipe_x(1)(0) := x_stage1(8)
  pipe_x(1)(1) := x_stage1(9)
  pipe_x(1)(2) := x_stage1(10)
  pipe_x(1)(3) := x_stage1(11)
  pipe_valid(1) := pipe_valid(0)

  // 流水线阶段2 (8-15轮)
  val x_stage2 = VecInit(Seq.fill(12)(0.U(32.W)))
  x_stage2(0) := pipe_x(1)(0)
  x_stage2(1) := pipe_x(1)(1)
  x_stage2(2) := pipe_x(1)(2)
  x_stage2(3) := pipe_x(1)(3)
  for (i <- 8 until 16) {
    val idx = i - 8
    x_stage2(idx+4) := x_stage2(idx) ^ ttrans(x_stage2(idx+1) ^ x_stage2(idx+2) ^ x_stage2(idx+3) ^ rk_sel(i))
  }
  pipe_x(2)(0) := x_stage2(8)
  pipe_x(2)(1) := x_stage2(9)
  pipe_x(2)(2) := x_stage2(10)
  pipe_x(2)(3) := x_stage2(11)
  pipe_valid(2) := pipe_valid(1)

  // 流水线阶段3 (16-23轮)
  val x_stage3 = VecInit(Seq.fill(12)(0.U(32.W)))
  x_stage3(0) := pipe_x(2)(0)
  x_stage3(1) := pipe_x(2)(1)
  x_stage3(2) := pipe_x(2)(2)
  x_stage3(3) := pipe_x(2)(3)
  for (i <- 16 until 24) {
    val idx = i - 16
    x_stage3(idx+4) := x_stage3(idx) ^ ttrans(x_stage3(idx+1) ^ x_stage3(idx+2) ^ x_stage3(idx+3) ^ rk_sel(i))
  }
  pipe_x(3)(0) := x_stage3(8)
  pipe_x(3)(1) := x_stage3(9)
  pipe_x(3)(2) := x_stage3(10)
  pipe_x(3)(3) := x_stage3(11)
  pipe_valid(3) := pipe_valid(2)

  // 流水线阶段4 (24-31轮)
  val x_stage4 = VecInit(Seq.fill(12)(0.U(32.W)))
  x_stage4(0) := pipe_x(3)(0)
  x_stage4(1) := pipe_x(3)(1)
  x_stage4(2) := pipe_x(3)(2)
  x_stage4(3) := pipe_x(3)(3)
  for (i <- 24 until 32) {
    val idx = i - 24
    x_stage4(idx+4) := x_stage4(idx) ^ ttrans(x_stage4(idx+1) ^ x_stage4(idx+2) ^ x_stage4(idx+3) ^ rk_sel(i))
  }
  pipe_valid(4) := pipe_valid(3)

  // 输出处理
  val mask = Cat(x_stage4(11), x_stage4(10), x_stage4(9), x_stage4(8))
  val ciphertext_reg = RegInit(0.U(128.W))
  val valid_reg = RegInit(false.B)

  when(pipe_valid(4)) {
    ciphertext_reg := io.plaintext ^ mask
    valid_reg := true.B
  }.otherwise {
    valid_reg := false.B
  }

  io.ciphertext := ciphertext_reg
  io.valid := valid_reg
}

// ==================== 5. 工具函数 ====================
object DmaSM4SGTools {
  // 32字节对齐
  def align32Byte(addr: UInt): UInt = (addr >> 5) << 5

  // 计算安全的burst长度（不跨页）
  def getSafeBurstLen(startAddr: UInt, remaining: UInt, beatBytes: Int = 32): UInt = {
    val pageMask = 0xFFF.U(32.W)
    val offset = startAddr & pageMask
    val bytesToPageEnd = Mux(offset === 0.U, 4096.U, (4096.U - offset) & pageMask)
    
    val maxInPage = bytesToPageEnd / beatBytes.U
    val maxByRemain = remaining / beatBytes.U
    val safeLen = Mux(maxInPage > 0.U, Mux(maxInPage < maxByRemain, maxInPage, maxByRemain), 1.U)
    Mux(safeLen > 15.U, 15.U, safeLen)
  }

  // PKCS#7补位
  def pkcs7Padding(data: UInt, validBytes: UInt): UInt = {
    val padLen = 16.U(5.W) - validBytes
    val padByte = padLen.asUInt
    val padValue = Cat(padByte, padByte, padByte, padByte, padByte, padByte, padByte, padByte)
    
    val paddedData = MuxLookup(validBytes, 0.U(128.W))(Seq(
      1.U(5.W)  -> Cat(Fill(15, padValue), data(7, 0)),
      2.U(5.W)  -> Cat(Fill(14, padValue), data(15, 0)),
      3.U(5.W)  -> Cat(Fill(13, padValue), data(23, 0)),
      4.U(5.W)  -> Cat(Fill(12, padValue), data(31, 0)),
      5.U(5.W)  -> Cat(Fill(11, padValue), data(39, 0)),
      6.U(5.W)  -> Cat(Fill(10, padValue), data(47, 0)),
      7.U(5.W)  -> Cat(Fill(9, padValue), data(55, 0)),
      8.U(5.W)  -> Cat(Fill(8, padValue), data(63, 0)),
      9.U(5.W)  -> Cat(Fill(7, padValue), data(71, 0)),
      10.U(5.W) -> Cat(Fill(6, padValue), data(79, 0)),
      11.U(5.W) -> Cat(Fill(5, padValue), data(87, 0)),
      12.U(5.W) -> Cat(Fill(4, padValue), data(95, 0)),
      13.U(5.W) -> Cat(Fill(3, padValue), data(103, 0)),
      14.U(5.W) -> Cat(Fill(2, padValue), data(111, 0)),
      15.U(5.W) -> Cat(Fill(1, padValue), data(119, 0)),
      16.U(5.W) -> data
    ))
    paddedData
  }

  // PKCS#7去补位
  def pkcs7Unpadding(data: UInt): (UInt, UInt) = {
    val padLen = data(7, 0)
    val padValid = padLen >= 1.U && padLen <= 16.U(5.W)
    val validData = MuxLookup(padLen, data)(Seq(
      1.U(5.W)  -> Cat(0.U(120.W), data(127, 120)),
      2.U(5.W)  -> Cat(0.U(112.W), data(127, 112)),
      3.U(5.W)  -> Cat(0.U(104.W), data(127, 104)),
      4.U(5.W)  -> Cat(0.U(96.W), data(127, 96)),
      5.U(5.W)  -> Cat(0.U(88.W), data(127, 88)),
      6.U(5.W)  -> Cat(0.U(80.W), data(127, 80)),
      7.U(5.W)  -> Cat(0.U(72.W), data(127, 72)),
      8.U(5.W)  -> Cat(0.U(64.W), data(127, 64)),
      9.U(5.W)  -> Cat(0.U(56.W), data(127, 56)),
      10.U(5.W) -> Cat(0.U(48.W), data(127, 48)),
      11.U(5.W) -> Cat(0.U(40.W), data(127, 40)),
      12.U(5.W) -> Cat(0.U(32.W), data(127, 32)),
      13.U(5.W) -> Cat(0.U(24.W), data(127, 24)),
      14.U(5.W) -> Cat(0.U(16.W), data(127, 16)),
      15.U(5.W) -> Cat(0.U(8.W), data(127, 8)),
      16.U(5.W) -> 0.U(128.W)
    ))
    val validBytes = 16.U(5.W) - Mux(padValid, padLen, 0.U)
    (validData, validBytes)
  }
}

// ==================== 6. 核心DMA控制器（带SG和SM4） ====================
class DMAControllerWithSM4SG extends Module {
  val io = IO(new Bundle {
    val apb  = new APB4SlaveIO()
    val axi  = new AXI4MasterIO()
    val busy = Output(Bool())
    val level = Output(UInt(8.W)) // FIFO水位
  })

  // -------------------- 状态定义（修正枚举语法） --------------------
  // 全局状态（正确的枚举定义方式）
  val globalStates = Enum(9)
    val Seq(sIdle, sRunning, sPadding, sUnpadding, sDone, sError,
      sSGReadDesc, sSGProcess, sSGNext) = globalStates
  val globalState = RegInit(sIdle)

  // 读状态机
  val readStates = Enum(3)
  val Seq(sRIdle, sRSetup, sRData) = readStates
  val readState = RegInit(sRIdle)

  // 写状态机
  val writeStates = Enum(3)
  val Seq(sWIdle, sWSetup, sWData) = writeStates
  val writeState = RegInit(sWIdle)

  // SG描述符读取状态机
  val sgReadStates = Enum(3)
  val sSGIdle :: sSGRead :: sSGWait :: Nil = sgReadStates
  val sgReadState = RegInit(sSGIdle)

  // -------------------- 寄存器定义 --------------------
  // 基础寄存器
  val regSrcAddr  = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val regDstAddr  = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val regTotalLen = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val regCtrl     = RegInit(0.U(32.W))
  val regStatus   = RegInit(0.U(32.W))
  val regSM4Key   = RegInit(VecInit(Seq.fill(4)(0.U(32.W))))
  val regSM4IV    = RegInit(VecInit(Seq.fill(4)(0.U(32.W))))

  // SG相关寄存器
  val regSGBaseAddr = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val regSGCurrAddr = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val regSGModeCtrl = RegInit(0.U(32.W))
  val regSGTotalCnt = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))

  // SG描述符缓存
  val regSGDesc = RegInit(0.U(256.W))
  val sgDesc = regSGDesc.asTypeOf(new SGDescriptor)

  // 传输状态寄存器
  val remainBytes = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val totalProcessed = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val lastBlockValidBytes = RegInit(0.U(5.W))
  val unpaddingValidBytes = RegInit(0.U(5.W))
  val sgDescReadCnt = RegInit(0.U(3.W))

  // -------------------- FIFO实例化 --------------------
  val readFifo = Module(new Queue(UInt(128.W), DmaSM4SGConfig.READ_FIFO_DEPTH))
  val cryptoFifo = Module(new Queue(UInt(128.W), DmaSM4SGConfig.CRYPTO_FIFO_DEPTH))
  
  // 初始化FIFO输入
  readFifo.io.enq.valid := false.B
  readFifo.io.enq.bits  := 0.U
  cryptoFifo.io.enq.valid := false.B
  cryptoFifo.io.enq.bits  := 0.U
  cryptoFifo.io.deq.ready := false.B

  // FIFO水位输出
  io.level := Cat(
    readFifo.io.count(log2Ceil(DmaSM4SGConfig.READ_FIFO_DEPTH)-1, 0),
    cryptoFifo.io.count(log2Ceil(DmaSM4SGConfig.CRYPTO_FIFO_DEPTH)-1, 0)
  )(7, 0)

  // -------------------- SM4实例化 --------------------
  val sm4 = Module(new SM4Pipeline8())
  sm4.io.en := false.B
  sm4.io.reset_iv := (globalState === sIdle)
  sm4.io.key := regSM4Key
  sm4.io.init_iv := regSM4IV
  sm4.io.plaintext := 0.U(128.W)
  // 默认模式，后续在需要时覆盖
  sm4.io.mode := false.B

  // -------------------- APB接口处理 --------------------
  io.apb.PREADY := true.B
  io.apb.PSLVERR := false.B
  io.apb.PRDATA := 0.U

  // 地址解码（取高5位以包含所有寄存器索引）
  val apbAddrSel = io.apb.PADDR(6, 2)

  // APB读操作
  when(io.apb.PSEL && !io.apb.PWRITE && io.apb.PENABLE) {
    switch(apbAddrSel) {
      is((DmaSM4SGConfig.REG_SRC_ADDR >> 2).U(5.W))  { io.apb.PRDATA := regSrcAddr }
      is((DmaSM4SGConfig.REG_DST_ADDR >> 2).U(5.W))  { io.apb.PRDATA := regDstAddr }
      is((DmaSM4SGConfig.REG_LENGTH >> 2).U(5.W))    { io.apb.PRDATA := regTotalLen }
      is((DmaSM4SGConfig.REG_CTRL >> 2).U(5.W))      { io.apb.PRDATA := regCtrl }
      is((DmaSM4SGConfig.REG_STATUS >> 2).U(5.W))    { io.apb.PRDATA := regStatus }
      is((DmaSM4SGConfig.REG_SM4_KEY0 >> 2).U(5.W))  { io.apb.PRDATA := regSM4Key(0) }
      is((DmaSM4SGConfig.REG_SM4_KEY1 >> 2).U(5.W))  { io.apb.PRDATA := regSM4Key(1) }
      is((DmaSM4SGConfig.REG_SM4_KEY2 >> 2).U(5.W))  { io.apb.PRDATA := regSM4Key(2) }
      is((DmaSM4SGConfig.REG_SM4_KEY3 >> 2).U(5.W))  { io.apb.PRDATA := regSM4Key(3) }
      is((DmaSM4SGConfig.REG_SM4_IV0 >> 2).U(5.W))   { io.apb.PRDATA := regSM4IV(0) }
      is((DmaSM4SGConfig.REG_SM4_IV1 >> 2).U(5.W))   { io.apb.PRDATA := regSM4IV(1) }
      is((DmaSM4SGConfig.REG_SM4_IV2 >> 2).U(5.W))   { io.apb.PRDATA := regSM4IV(2) }
      is((DmaSM4SGConfig.REG_SM4_IV3 >> 2).U(5.W))   { io.apb.PRDATA := regSM4IV(3) }
      is((DmaSM4SGConfig.REG_SG_BASE >> 2).U(5.W))   { io.apb.PRDATA := regSGBaseAddr }
      is((DmaSM4SGConfig.REG_SG_CURR >> 2).U(5.W))   { io.apb.PRDATA := regSGCurrAddr }
      is((DmaSM4SGConfig.REG_SG_CTRL >> 2).U(5.W))   { io.apb.PRDATA := regSGModeCtrl }
      is((DmaSM4SGConfig.REG_SG_TOTAL >> 2).U(5.W))  { io.apb.PRDATA := regSGTotalCnt }
    }
  }

  // APB写操作
  when(io.apb.PSEL && io.apb.PWRITE && io.apb.PENABLE && !regStatus(0)) {
    switch(apbAddrSel) {
      is((DmaSM4SGConfig.REG_SRC_ADDR >> 2).U(5.W))  { regSrcAddr := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_DST_ADDR >> 2).U(5.W))  { regDstAddr := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_LENGTH >> 2).U(5.W))    { regTotalLen := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_CTRL >> 2).U(5.W))      {
        val clearMask = ~((1.U << DmaSM4SGConfig.CTRL_DONE) | (1.U << DmaSM4SGConfig.CTRL_ERROR))
        regCtrl := io.apb.PWDATA & clearMask
      }
      is((DmaSM4SGConfig.REG_SM4_KEY0 >> 2).U(5.W))  { regSM4Key(0) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_KEY1 >> 2).U(5.W))  { regSM4Key(1) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_KEY2 >> 2).U(5.W))  { regSM4Key(2) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_KEY3 >> 2).U(5.W))  { regSM4Key(3) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_IV0 >> 2).U(5.W))   { regSM4IV(0) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_IV1 >> 2).U(5.W))   { regSM4IV(1) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_IV2 >> 2).U(5.W))   { regSM4IV(2) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SM4_IV3 >> 2).U(5.W))   { regSM4IV(3) := io.apb.PWDATA }
      is((DmaSM4SGConfig.REG_SG_BASE >> 2).U(5.W))   { 
        regSGBaseAddr := DmaSM4SGTools.align32Byte(io.apb.PWDATA) 
      }
      is((DmaSM4SGConfig.REG_SG_CTRL >> 2).U(5.W))   { 
        val clearMask = ~((1.U << DmaSM4SGConfig.SG_CTRL_DONE) | (1.U << DmaSM4SGConfig.SG_CTRL_ERROR))
        regSGModeCtrl := io.apb.PWDATA & clearMask 
      }
    }
  }

  // -------------------- AXI读通道 --------------------
  val readAddr   = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val readBurst  = RegInit(0.U(4.W))
  val readBeatCnt = RegInit(0.U(4.W))
  
  // 初始化读通道信号
  io.axi.araddr  := 0.U
  io.axi.arburst := 1.U  // 增量burst
  io.axi.arsize  := 5.U  // 32字节
  io.axi.arlen   := 0.U
  io.axi.arvalid := false.B
  io.axi.rready   := false.B

  switch(readState) {
    is(sRIdle) {
      when((globalState === sRunning || globalState === sSGProcess) && 
           readFifo.io.count < (DmaSM4SGConfig.READ_FIFO_DEPTH - 4).U) {
        // 选择源地址（SG模式/普通模式）
        readAddr := Mux(readAddr === 0.U, 
          Mux(globalState === sSGProcess, sgDesc.src_addr, regSrcAddr), 
          readAddr
        )
        readState := sRSetup
      }
    }

    is(sRSetup) {
      // 计算安全的burst长度
      val safeLen = DmaSM4SGTools.getSafeBurstLen(readAddr, remainBytes)
      readBurst := Mux(safeLen > DmaSM4SGConfig.AXI_BURST_MAX_LEN.U, 
                       DmaSM4SGConfig.AXI_BURST_MAX_LEN.U, safeLen)
      
      // 发送读地址
      io.axi.araddr  := readAddr
      io.axi.arlen   := readBurst - 1.U
      io.axi.arvalid := true.B

      when(io.axi.arready) {
        io.axi.arvalid := false.B
        readBeatCnt := 0.U
        readState := sRData
        io.axi.rready := true.B
      }
    }

    is(sRData) {
      io.axi.rready := true.B
      
      when(io.axi.rvalid) {
        // 拆分256位数据为两个128位
        val data_256b = io.axi.rdata
        val data1_128b = data_256b(127, 0)
        val data2_128b = data_256b(255, 128)
        
        // 计算本次要读取的字节数
        val bytesToRead = Mux(remainBytes >= DmaSM4SGConfig.BEAT_BYTES.U, 
                              DmaSM4SGConfig.BEAT_BYTES.U, remainBytes)
        
        // 处理数据写入FIFO
        when(bytesToRead >= 16.U(5.W)) {
          // 至少16字节
          readFifo.io.enq.valid := true.B
          readFifo.io.enq.bits := data1_128b
          remainBytes := remainBytes - 16.U(5.W)
          
          // 如果超过16字节，写入第二个128位
          when(bytesToRead > 16.U(5.W)) {
            val enq2 = readFifo.io.enq.fire && (bytesToRead > 16.U(5.W))
            when(enq2) {
              readFifo.io.enq.bits := data2_128b
              remainBytes := remainBytes - 16.U(5.W)
            }
          }.otherwise {
            lastBlockValidBytes := 16.U(5.W)
          }
        }.otherwise {
          // 不足16字节，记录有效字节数
          lastBlockValidBytes := bytesToRead(3, 0)
          // 拼接部分数据
          val partialData = MuxLookup(bytesToRead, 0.U(128.W))(Seq(
            1.U(5.W)  -> Cat(0.U(120.W), data_256b(7, 0)),
            2.U(5.W)  -> Cat(0.U(112.W), data_256b(15, 0)),
            3.U(5.W)  -> Cat(0.U(104.W), data_256b(23, 0)),
            4.U(5.W)  -> Cat(0.U(96.W), data_256b(31, 0)),
            5.U(5.W)  -> Cat(0.U(88.W), data_256b(39, 0)),
            6.U(5.W)  -> Cat(0.U(80.W), data_256b(47, 0)),
            7.U(5.W)  -> Cat(0.U(72.W), data_256b(55, 0)),
            8.U(5.W)  -> Cat(0.U(64.W), data_256b(63, 0)),
            9.U(5.W)  -> Cat(0.U(56.W), data_256b(71, 0)),
            10.U(5.W) -> Cat(0.U(48.W), data_256b(79, 0)),
            11.U(5.W) -> Cat(0.U(40.W), data_256b(87, 0)),
            12.U(5.W) -> Cat(0.U(32.W), data_256b(95, 0)),
            13.U(5.W) -> Cat(0.U(24.W), data_256b(103, 0)),
            14.U(5.W) -> Cat(0.U(16.W), data_256b(111, 0)),
            15.U(5.W) -> Cat(0.U(8.W), data_256b(119, 0))
          ))
          readFifo.io.enq.valid := true.B
          readFifo.io.enq.bits := partialData
          remainBytes := 0.U
        }
        
        // 更新计数器和地址
        readBeatCnt := readBeatCnt + 1.U
        readAddr := DmaSM4SGTools.align32Byte(readAddr + DmaSM4SGConfig.BEAT_BYTES.U)

        // 判断burst结束
        val burstEnd = io.axi.rlast || (readBeatCnt === readBurst) || (remainBytes === 0.U)
        when(burstEnd) {
          io.axi.rready := false.B
          readState := Mux(
            (globalState === sRunning || globalState === sSGProcess) && remainBytes > 0.U, 
            sRSetup, 
            sRIdle
          )
          
          // 读取完成，进入补位/去补位阶段
          when(remainBytes === 0.U) {
            val cryptoMode = Mux(globalState === sSGProcess, 
                                sgDesc.ctrl(DmaSM4SGConfig.DESC_CTRL_CRYPTO_MODE),
                                regCtrl(DmaSM4SGConfig.CTRL_CRYPTO_MODE))
            globalState := Mux(cryptoMode, sUnpadding, sPadding)
          }
        }
      }
    }
  }

  // -------------------- SM4加解密处理 --------------------
  // 加解密触发条件
  val cryptoEn = Mux(globalState === sSGProcess, 
                     sgDesc.ctrl(DmaSM4SGConfig.DESC_CTRL_CRYPTO_EN),
                     regCtrl(DmaSM4SGConfig.CTRL_CRYPTO_EN))
                     
  val cryptoTrigger = (readFifo.io.deq.valid && 
                       cryptoFifo.io.count < (DmaSM4SGConfig.CRYPTO_FIFO_DEPTH - 1).U && 
                       cryptoEn)
                       
  val paddingTrigger = (globalState === sPadding && readFifo.io.deq.valid)
  val unpaddingTrigger = (globalState === sUnpadding && readFifo.io.deq.valid)

  // 数据处理
  when(cryptoTrigger || paddingTrigger || unpaddingTrigger) {
    readFifo.io.deq.ready := true.B
    
    // 补位处理
    val plaintext = Mux(globalState === sPadding,
      DmaSM4SGTools.pkcs7Padding(readFifo.io.deq.bits, lastBlockValidBytes),
      readFifo.io.deq.bits
    )
    
    // 送入SM4模块
    sm4.io.plaintext := plaintext
    sm4.io.mode := Mux(globalState === sSGProcess, 
                       sgDesc.ctrl(DmaSM4SGConfig.DESC_CTRL_CRYPTO_MODE),
                       regCtrl(DmaSM4SGConfig.CTRL_CRYPTO_MODE))
    sm4.io.en := true.B
    
    // SM4输出处理
    when(sm4.io.valid) {
      cryptoFifo.io.enq.valid := true.B
      
      // 去补位处理
      val (unpaddedData, validBytes) = DmaSM4SGTools.pkcs7Unpadding(sm4.io.ciphertext)
      cryptoFifo.io.enq.bits := Mux(globalState === sUnpadding, unpaddedData, sm4.io.ciphertext)
      
      // 记录去补位后的有效字节数
      when(globalState === sUnpadding) {
        unpaddingValidBytes := validBytes
      }
    }
  }.otherwise {
    readFifo.io.deq.ready := false.B
  }

  // -------------------- AXI写通道 --------------------
  val writeAddr   = RegInit(0.U(DmaSM4SGConfig.AXI_ADDR_WIDTH.W))
  val writeBurst  = RegInit(0.U(4.W))
  val writeBeatCnt = RegInit(0.U(4.W))
  val writeDataReg = RegInit(0.U(DmaSM4SGConfig.AXI_DATA_WIDTH.W))

  // 写通道信号初始化
  io.axi.awaddr  := 0.U
  io.axi.awburst := 1.U
  io.axi.awsize  := 5.U
  io.axi.awlen   := 0.U
  io.axi.awvalid := false.B
  
  io.axi.wdata  := 0.U
  io.axi.wstrb  := Fill(DmaSM4SGConfig.BEAT_BYTES, 1.U(1.W))
  io.axi.wlast  := false.B
  io.axi.wvalid := false.B
  io.axi.bready := true.B

  // 128位数据拼接为256位
  val collect128bit = RegInit(false.B)
  val first128bit = RegInit(0.U(128.W))
  val isLastBlock = RegInit(false.B)

  switch(writeState) {
    is(sWIdle) {
      when(cryptoFifo.io.deq.valid && 
           (globalState === sRunning || globalState === sPadding || 
            globalState === sUnpadding || globalState === sSGProcess)) {
        // 选择目的地址
        writeAddr := Mux(writeAddr === 0.U, 
          Mux(globalState === sSGProcess, sgDesc.dst_addr, regDstAddr), 
          writeAddr
        )
        writeState := sWSetup
        collect128bit := false.B
        isLastBlock := (globalState === sPadding || globalState === sUnpadding)
      }
    }

    is(sWSetup) {
      // 计算burst长度
      val fifoCount = cryptoFifo.io.count
      val burstLen = Mux(fifoCount >= 2.U, 
                        Mux(fifoCount > (DmaSM4SGConfig.AXI_BURST_MAX_LEN * 2).U, 
                            DmaSM4SGConfig.AXI_BURST_MAX_LEN.U, (fifoCount / 2.U)), 
                        1.U)
      writeBurst := burstLen
      
      // 发送写地址
      io.axi.awaddr  := writeAddr
      io.axi.awlen   := burstLen - 1.U
      io.axi.awvalid := true.B

      when(io.axi.awready) {
        io.axi.awvalid := false.B
        writeBeatCnt := 0.U
        writeState := sWData
      }
    }

    is(sWData) {
      // 拼接128位数据为256位
      when(cryptoFifo.io.deq.valid && !collect128bit) {
        first128bit := cryptoFifo.io.deq.bits
        cryptoFifo.io.deq.ready := true.B
        collect128bit := true.B
      }.elsewhen(cryptoFifo.io.deq.valid && collect128bit) {
        writeDataReg := Cat(cryptoFifo.io.deq.bits, first128bit)
        cryptoFifo.io.deq.ready := true.B
        collect128bit := false.B
        
        // 发送写数据
        io.axi.wdata  := writeDataReg
        io.axi.wvalid := true.B
        io.axi.wlast  := (writeBeatCnt === writeBurst - 1.U) || 
             (isLastBlock && unpaddingValidBytes < 16.U(5.W))

        // 处理解密去补位后的字节选通
        when(isLastBlock && 
             Mux(globalState === sSGProcess, 
                 sgDesc.ctrl(DmaSM4SGConfig.DESC_CTRL_CRYPTO_MODE),
                 regCtrl(DmaSM4SGConfig.CTRL_CRYPTO_MODE)) && 
             unpaddingValidBytes < 16.U(5.W)) {
          val wstrb = MuxLookup(unpaddingValidBytes, 
                               Fill(DmaSM4SGConfig.BEAT_BYTES, 1.U(1.W)))(Seq(
            1.U(5.W)  -> Cat(Fill(31, 0.U(1.W)), 1.U(1.W)),
            2.U(5.W)  -> Cat(Fill(30, 0.U(1.W)), Fill(2, 1.U(1.W))),
            3.U(5.W)  -> Cat(Fill(29, 0.U(1.W)), Fill(3, 1.U(1.W))),
            4.U(5.W)  -> Cat(Fill(28, 0.U(1.W)), Fill(4, 1.U(1.W))),
            5.U(5.W)  -> Cat(Fill(27, 0.U(1.W)), Fill(5, 1.U(1.W))),
            6.U(5.W)  -> Cat(Fill(26, 0.U(1.W)), Fill(6, 1.U(1.W))),
            7.U(5.W)  -> Cat(Fill(25, 0.U(1.W)), Fill(7, 1.U(1.W))),
            8.U(5.W)  -> Cat(Fill(24, 0.U(1.W)), Fill(8, 1.U(1.W))),
            9.U(5.W)  -> Cat(Fill(23, 0.U(1.W)), Fill(9, 1.U(1.W))),
            10.U(5.W) -> Cat(Fill(22, 0.U(1.W)), Fill(10, 1.U(1.W))),
            11.U(5.W) -> Cat(Fill(21, 0.U(1.W)), Fill(11, 1.U(1.W))),
            12.U(5.W) -> Cat(Fill(20, 0.U(1.W)), Fill(12, 1.U(1.W))),
            13.U(5.W) -> Cat(Fill(19, 0.U(1.W)), Fill(13, 1.U(1.W))),
            14.U(5.W) -> Cat(Fill(18, 0.U(1.W)), Fill(14, 1.U(1.W))),
            15.U(5.W) -> Cat(Fill(17, 0.U(1.W)), Fill(15, 1.U(1.W)))
          ))
          io.axi.wstrb := wstrb
        }

        // 写响应处理
        when(io.axi.wready) {
          writeBeatCnt := writeBeatCnt + 1.U
          totalProcessed := totalProcessed + DmaSM4SGConfig.BEAT_BYTES.U
          regSGTotalCnt := regSGTotalCnt + DmaSM4SGConfig.BEAT_BYTES.U

          // 更新写地址
          writeAddr := DmaSM4SGTools.align32Byte(writeAddr + DmaSM4SGConfig.BEAT_BYTES.U)

          // 判断burst结束
          val burstEnd = io.axi.wlast || (cryptoFifo.io.count === 0.U && globalState === sDone)
          when(burstEnd) {
            io.axi.wvalid := false.B
            writeState := Mux(
              cryptoFifo.io.deq.valid && 
              (globalState === sRunning || globalState === sPadding || 
               globalState === sUnpadding || globalState === sSGProcess), 
              sWSetup, 
              sWIdle
            )
            
            // 所有数据写入完成
            when(cryptoFifo.io.count === 0.U && 
                 (globalState === sPadding || globalState === sUnpadding)) {
              globalState := Mux(globalState === sSGProcess, sSGNext, sDone)
            }
          }
        }
      }
    }
  }

  // -------------------- SG描述符读取 --------------------
  switch(sgReadState) {
    is(sSGIdle) {
      when(globalState === sSGReadDesc) {
        // 读取32字节描述符
        io.axi.araddr  := regSGCurrAddr
        io.axi.arburst := 1.U
        io.axi.arsize  := 5.U
        io.axi.arlen   := 7.U  // 8个beat = 32字节
        io.axi.arvalid := true.B
        sgDescReadCnt := 0.U
        sgReadState := sSGRead
      }
    }

    is(sSGRead) {
      io.axi.rready := true.B
      when(io.axi.arready) {
        io.axi.arvalid := false.B
      }

      when(io.axi.rvalid) {
        // 拼接描述符数据
        regSGDesc := Cat(io.axi.rdata, regSGDesc(255, 32))
        sgDescReadCnt := sgDescReadCnt + 1.U

        // 描述符读取完成
        when(sgDescReadCnt === 7.U || io.axi.rlast) {
          io.axi.rready := false.B
          sgReadState := sSGWait
          globalState := sSGProcess
          // 初始化传输参数
          remainBytes := sgDesc.length
          totalProcessed := 0.U
          lastBlockValidBytes := 0.U
          unpaddingValidBytes := 0.U
        }
      }
    }

    is(sSGWait) {
      when(globalState =/= sSGProcess) {
        sgReadState := sSGIdle
      }
    }
  }

  // -------------------- 全局状态机 --------------------
  switch(globalState) {
    is(sIdle) {
      // 优先SG模式
      when(regSGModeCtrl(DmaSM4SGConfig.SG_CTRL_EN) && 
           regSGModeCtrl(DmaSM4SGConfig.SG_CTRL_START) && 
           !regSGModeCtrl(DmaSM4SGConfig.SG_CTRL_DONE) && 
           !regSGModeCtrl(DmaSM4SGConfig.SG_CTRL_ERROR)) {
        regSGCurrAddr := regSGBaseAddr
        regSGTotalCnt := 0.U
        globalState := sSGReadDesc
      }.elsewhen(regCtrl(DmaSM4SGConfig.CTRL_START) && !regStatus(0)) {
        // 普通模式启动
        when(regTotalLen === 0.U) {
          regCtrl := regCtrl | (1.U << DmaSM4SGConfig.CTRL_DONE)
        }.otherwise {
          remainBytes := regTotalLen
          readAddr := regSrcAddr
          writeAddr := regDstAddr
          totalProcessed := 0.U
          lastBlockValidBytes := 0.U
          unpaddingValidBytes := 0.U
          globalState := sRunning
        }
      }
    }

    is(sRunning) { /* 传输中 */ }
    is(sPadding) { /* 加密补位 */ }
    is(sUnpadding) { /* 解密去补位 */ }

    is(sDone) {
      // 普通模式完成
      regStatus := regStatus | (1.U << 0)
      regCtrl := regCtrl | (1.U << DmaSM4SGConfig.CTRL_DONE)
      globalState := sIdle
    }

    is(sError) {
      // 错误处理
      regSGModeCtrl := regSGModeCtrl | (1.U << DmaSM4SGConfig.SG_CTRL_ERROR)
      regStatus := regStatus | (1.U << DmaSM4SGConfig.CTRL_ERROR)
      globalState := sIdle
    }

    is(sSGReadDesc) { /* 读取描述符 */ }
    is(sSGProcess) { /* 处理当前描述符 */ }

    is(sSGNext) {
      // 检查结束标志
      when(sgDesc.ctrl(DmaSM4SGConfig.DESC_CTRL_END)) {
        // SG传输完成
        regSGModeCtrl := regSGModeCtrl | (1.U << DmaSM4SGConfig.SG_CTRL_DONE)
        globalState := sIdle
      }.otherwise {
        // 下一个描述符
        regSGCurrAddr := regSGCurrAddr + 32.U
        globalState := sSGReadDesc
      }
    }
  }

  // -------------------- 错误处理 --------------------
  when(io.axi.rvalid && io.axi.rresp =/= 0.U) {
    globalState := sError
  }

  when(io.axi.bvalid && io.axi.bresp =/= 0.U) {
    globalState := sError
  }

  // -------------------- 忙状态输出 --------------------
  io.busy := (globalState =/= sIdle)
}

// ==================== 7. 顶层模块（可选） ====================
class DmaSM4SGTop extends Module {
  val io = IO(new Bundle {
    val apb  = new APB4SlaveIO()
    val axi  = new AXI4MasterIO()
    val busy = Output(Bool())
    val level = Output(UInt(8.W))
  })

  val dma = Module(new DMAControllerWithSM4SG())
  io.apb <> dma.io.apb
  io.axi <> dma.io.axi
  io.busy := dma.io.busy
  io.level := dma.io.level
}

// ==================== 8. 生成Verilog（主函数） ====================
object DmaSM4SGGenerator extends App {
  _root_.circt.stage.ChiselStage.emitSystemVerilogFile(
    new DmaSM4SGTop(),
    Array("--target-dir=outputDMAController")
  )
}