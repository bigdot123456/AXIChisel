package dmaAXI

import chisel3._
import chisel3.util._

// ==================== 1. 4周期流水线SM4加解密模块（复用硬件） ====================
class SM4Pipeline_4Cycle extends Module {
  val io = IO(new Bundle {
    // 控制信号
    val en = Input(Bool())        // 加密/解密使能
    val reset_iv = Input(Bool())  // 重置IV
    val mode = Input(Bool())      // 0=加密，1=解密
    
    // 配置接口
    val key = Input(Vec(4, UInt(32.W)))  // 加解密密钥（共用）
    val init_iv = Input(Vec(4, UInt(32.W))) // 初始IV
    
    // 数据接口（128bit粒度）
    val plaintext = Input(UInt(128.W))   // 明文（加密）/密文（解密）
    val ciphertext = Output(UInt(128.W)) // 密文（加密）/明文（解密）
    val valid = Output(Bool())           // 计算完成有效
    val iv_out = Output(Vec(4, UInt(32.W))) // 当前IV
  })

  // -------------------- 1. SM4基础定义 --------------------
  // SM4 S盒（国标GB/T 32907-2016）
  val SBOX = VecInit(
    BigInt("d6", 16).U(8.W), BigInt("90", 16).U(8.W), BigInt("e9", 16).U(8.W), BigInt("fe", 16).U(8.W),
    BigInt("cc", 16).U(8.W), BigInt("e1", 16).U(8.W), BigInt("3d", 16).U(8.W), BigInt("b7", 16).U(8.W),
    BigInt("16", 16).U(8.W), BigInt("b6", 16).U(8.W), BigInt("14", 16).U(8.W), BigInt("c2", 16).U(8.W),
    BigInt("28", 16).U(8.W), BigInt("fb", 16).U(8.W), BigInt("2c", 16).U(8.W), BigInt("05", 16).U(8.W),
    BigInt("2b", 16).U(8.W), BigInt("67", 16).U(8.W), BigInt("9a", 16).U(8.W), BigInt("76", 16).U(8.W),
    BigInt("2a", 16).U(8.W), BigInt("be", 16).U(8.W), BigInt("04", 16).U(8.W), BigInt("c3", 16).U(8.W),
    BigInt("aa", 16).U(8.W), BigInt("44", 16).U(8.W), BigInt("13", 16).U(8.W), BigInt("26", 16).U(8.W),
    BigInt("49", 16).U(8.W), BigInt("86", 16).U(8.W), BigInt("06", 16).U(8.W), BigInt("99", 16).U(8.W),
    BigInt("9c", 16).U(8.W), BigInt("42", 16).U(8.W), BigInt("50", 16).U(8.W), BigInt("f4", 16).U(8.W),
    BigInt("91", 16).U(8.W), BigInt("ef", 16).U(8.W), BigInt("98", 16).U(8.W), BigInt("7a", 16).U(8.W),
    BigInt("33", 16).U(8.W), BigInt("54", 16).U(8.W), BigInt("0b", 16).U(8.W), BigInt("43", 16).U(8.W),
    BigInt("ed", 16).U(8.W), BigInt("cf", 16).U(8.W), BigInt("ac", 16).U(8.W), BigInt("62", 16).U(8.W),
    BigInt("e4", 16).U(8.W), BigInt("b3", 16).U(8.W), BigInt("1c", 16).U(8.W), BigInt("a9", 16).U(8.W),
    BigInt("c9", 16).U(8.W), BigInt("08", 16).U(8.W), BigInt("e8", 16).U(8.W), BigInt("95", 16).U(8.W),
    BigInt("80", 16).U(8.W), BigInt("df", 16).U(8.W), BigInt("94", 16).U(8.W), BigInt("fa", 16).U(8.W),
    BigInt("75", 16).U(8.W), BigInt("8f", 16).U(8.W), BigInt("3f", 16).U(8.W), BigInt("a6", 16).U(8.W),
    BigInt("47", 16).U(8.W), BigInt("07", 16).U(8.W), BigInt("a7", 16).U(8.W), BigInt("fc", 16).U(8.W),
    BigInt("f3", 16).U(8.W), BigInt("73", 16).U(8.W), BigInt("17", 16).U(8.W), BigInt("ba", 16).U(8.W),
    BigInt("83", 16).U(8.W), BigInt("59", 16).U(8.W), BigInt("3c", 16).U(8.W), BigInt("19", 16).U(8.W),
    BigInt("e6", 16).U(8.W), BigInt("85", 16).U(8.W), BigInt("4f", 16).U(8.W), BigInt("a8", 16).U(8.W),
    BigInt("68", 16).U(8.W), BigInt("6b", 16).U(8.W), BigInt("81", 16).U(8.W), BigInt("b2", 16).U(8.W),
    BigInt("71", 16).U(8.W), BigInt("64", 16).U(8.W), BigInt("da", 16).U(8.W), BigInt("8b", 16).U(8.W),
    BigInt("f8", 16).U(8.W), BigInt("eb", 16).U(8.W), BigInt("0f", 16).U(8.W), BigInt("4b", 16).U(8.W),
    BigInt("70", 16).U(8.W), BigInt("56", 16).U(8.W), BigInt("9d", 16).U(8.W), BigInt("35", 16).U(8.W),
    BigInt("1e", 16).U(8.W), BigInt("24", 16).U(8.W), BigInt("0e", 16).U(8.W), BigInt("5e", 16).U(8.W),
    BigInt("63", 16).U(8.W), BigInt("58", 16).U(8.W), BigInt("d1", 16).U(8.W), BigInt("a2", 16).U(8.W),
    BigInt("25", 16).U(8.W), BigInt("22", 16).U(8.W), BigInt("7c", 16).U(8.W), BigInt("3b", 16).U(8.W),
    BigInt("01", 16).U(8.W), BigInt("21", 16).U(8.W), BigInt("78", 16).U(8.W), BigInt("87", 16).U(8.W),
    BigInt("d4", 16).U(8.W), BigInt("00", 16).U(8.W), BigInt("46", 16).U(8.W), BigInt("57", 16).U(8.W),
    BigInt("9f", 16).U(8.W), BigInt("d3", 16).U(8.W), BigInt("27", 16).U(8.W), BigInt("52", 16).U(8.W),
    BigInt("4c", 16).U(8.W), BigInt("36", 16).U(8.W), BigInt("02", 16).U(8.W), BigInt("e7", 16).U(8.W),
    BigInt("a0", 16).U(8.W), BigInt("c4", 16).U(8.W), BigInt("c8", 16).U(8.W), BigInt("9e", 16).U(8.W),
    BigInt("ea", 16).U(8.W), BigInt("bf", 16).U(8.W), BigInt("8a", 16).U(8.W), BigInt("d2", 16).U(8.W),
    BigInt("40", 16).U(8.W), BigInt("c7", 16).U(8.W), BigInt("38", 16).U(8.W), BigInt("b5", 16).U(8.W),
    BigInt("a3", 16).U(8.W), BigInt("f7", 16).U(8.W), BigInt("f2", 16).U(8.W), BigInt("ce", 16).U(8.W),
    BigInt("f9", 16).U(8.W), BigInt("61", 16).U(8.W), BigInt("15", 16).U(8.W), BigInt("a1", 16).U(8.W),
    BigInt("e0", 16).U(8.W), BigInt("ae", 16).U(8.W), BigInt("5d", 16).U(8.W), BigInt("a4", 16).U(8.W),
    BigInt("9b", 16).U(8.W), BigInt("34", 16).U(8.W), BigInt("1a", 16).U(8.W), BigInt("55", 16).U(8.W),
    BigInt("ad", 16).U(8.W), BigInt("93", 16).U(8.W), BigInt("32", 16).U(8.W), BigInt("30", 16).U(8.W),
    BigInt("f5", 16).U(8.W), BigInt("8c", 16).U(8.W), BigInt("b1", 16).U(8.W), BigInt("e3", 16).U(8.W),
    BigInt("1d", 16).U(8.W), BigInt("f6", 16).U(8.W), BigInt("e2", 16).U(8.W), BigInt("2e", 16).U(8.W),
    BigInt("82", 16).U(8.W), BigInt("66", 16).U(8.W), BigInt("ca", 16).U(8.W), BigInt("60", 16).U(8.W),
    BigInt("c0", 16).U(8.W), BigInt("29", 16).U(8.W), BigInt("23", 16).U(8.W), BigInt("ab", 16).U(8.W),
    BigInt("0d", 16).U(8.W), BigInt("53", 16).U(8.W), BigInt("4e", 16).U(8.W), BigInt("6f", 16).U(8.W),
    BigInt("d5", 16).U(8.W), BigInt("db", 16).U(8.W), BigInt("37", 16).U(8.W), BigInt("45", 16).U(8.W),
    BigInt("de", 16).U(8.W), BigInt("fd", 16).U(8.W), BigInt("8e", 16).U(8.W), BigInt("2f", 16).U(8.W),
    BigInt("03", 16).U(8.W), BigInt("ff", 16).U(8.W), BigInt("6a", 16).U(8.W), BigInt("72", 16).U(8.W),
    BigInt("6d", 16).U(8.W), BigInt("6c", 16).U(8.W), BigInt("5b", 16).U(8.W), BigInt("51", 16).U(8.W),
    BigInt("8d", 16).U(8.W), BigInt("1b", 16).U(8.W), BigInt("af", 16).U(8.W), BigInt("92", 16).U(8.W),
    BigInt("bb", 16).U(8.W), BigInt("dd", 16).U(8.W), BigInt("bc", 16).U(8.W), BigInt("7f", 16).U(8.W),
    BigInt("11", 16).U(8.W), BigInt("d9", 16).U(8.W), BigInt("5c", 16).U(8.W), BigInt("41", 16).U(8.W),
    BigInt("1f", 16).U(8.W), BigInt("10", 16).U(8.W), BigInt("5a", 16).U(8.W), BigInt("d8", 16).U(8.W),
    BigInt("0a", 16).U(8.W), BigInt("c1", 16).U(8.W), BigInt("31", 16).U(8.W), BigInt("88", 16).U(8.W),
    BigInt("a5", 16).U(8.W), BigInt("cd", 16).U(8.W), BigInt("7b", 16).U(8.W), BigInt("bd", 16).U(8.W),
    BigInt("2d", 16).U(8.W), BigInt("74", 16).U(8.W), BigInt("d0", 16).U(8.W), BigInt("12", 16).U(8.W),
    BigInt("b8", 16).U(8.W), BigInt("e5", 16).U(8.W), BigInt("b4", 16).U(8.W), BigInt("b0", 16).U(8.W),
    BigInt("89", 16).U(8.W), BigInt("69", 16).U(8.W), BigInt("97", 16).U(8.W), BigInt("4a", 16).U(8.W),
    BigInt("0c", 16).U(8.W), BigInt("96", 16).U(8.W), BigInt("77", 16).U(8.W), BigInt("7e", 16).U(8.W),
    BigInt("65", 16).U(8.W), BigInt("b9", 16).U(8.W), BigInt("f1", 16).U(8.W), BigInt("09", 16).U(8.W),
    BigInt("c5", 16).U(8.W), BigInt("6e", 16).U(8.W), BigInt("c6", 16).U(8.W), BigInt("84", 16).U(8.W),
    BigInt("18", 16).U(8.W), BigInt("f0", 16).U(8.W), BigInt("7d", 16).U(8.W), BigInt("ec", 16).U(8.W),
    BigInt("3a", 16).U(8.W), BigInt("dc", 16).U(8.W), BigInt("4d", 16).U(8.W), BigInt("20", 16).U(8.W),
    BigInt("79", 16).U(8.W), BigInt("ee", 16).U(8.W), BigInt("5f", 16).U(8.W), BigInt("3e", 16).U(8.W),
    BigInt("d7", 16).U(8.W), BigInt("cb", 16).U(8.W), BigInt("39", 16).U(8.W), BigInt("48", 16).U(8.W)
  )

  // SM4常量
  val FK = VecInit(
    BigInt("a3b1bac6", 16).U(32.W),
    BigInt("56aa3350", 16).U(32.W),
    BigInt("677d9197", 16).U(32.W),
    BigInt("b27022dc", 16).U(32.W)
  )

  val CK = VecInit(
    BigInt("00070e15", 16).U(32.W), BigInt("1c232a31", 16).U(32.W),
    BigInt("383f464d", 16).U(32.W), BigInt("545b6269", 16).U(32.W),
    BigInt("70777e85", 16).U(32.W), BigInt("8c939aa1", 16).U(32.W),
    BigInt("a8afb6bd", 16).U(32.W), BigInt("c4cbd2d9", 16).U(32.W),
    BigInt("e0e7eef5", 16).U(32.W), BigInt("fc030a11", 16).U(32.W),
    BigInt("181f262d", 16).U(32.W), BigInt("343b4249", 16).U(32.W),
    BigInt("50575e65", 16).U(32.W), BigInt("6c737a81", 16).U(32.W),
    BigInt("888f969d", 16).U(32.W), BigInt("a4abb2b9", 16).U(32.W),
    BigInt("c0c7ced5", 16).U(32.W), BigInt("dce3eaf1", 16).U(32.W),
    BigInt("f8ff060d", 16).U(32.W), BigInt("141b2229", 16).U(32.W),
    BigInt("30373e45", 16).U(32.W), BigInt("4c535a61", 16).U(32.W),
    BigInt("686f767d", 16).U(32.W), BigInt("848b9299", 16).U(32.W),
    BigInt("a0a7aeb5", 16).U(32.W), BigInt("bcc3cad1", 16).U(32.W),
    BigInt("d8dfe6ed", 16).U(32.W), BigInt("f4fb0209", 16).U(32.W),
    BigInt("10171e25", 16).U(32.W), BigInt("2c333a41", 16).U(32.W),
    BigInt("484f565d", 16).U(32.W), BigInt("646b7279", 16).U(32.W)
  )

  // -------------------- 2. SM4核心函数 --------------------
  def sboxSub(in: UInt): UInt = {
    val bytes = VecInit((0 to 3).map(i => in(8*(3-i)+7, 8*(3-i))))
    VecInit(bytes.map(b => SBOX(b))).asUInt
  }

  def rotl(in: UInt, n: Int): UInt = (in << n) | (in >> (32 - n))
  def ltrans(in: UInt): UInt = in ^ rotl(in, 2) ^ rotl(in, 10) ^ rotl(in, 18) ^ rotl(in, 24)
  def ttrans(in: UInt): UInt = ltrans(sboxSub(in))
  def keyExp(in: UInt, ck: UInt): UInt = in ^ ttrans(in ^ rotl(in, 13) ^ rotl(in, 23) ^ ck)

  // -------------------- 3. 密钥扩展 --------------------
  val rk = VecInit(Seq.fill(32)(0.U(32.W))) // 加密轮密钥RK[0-31]
  val mk = VecInit((0 to 3).map(i => io.key(i) ^ FK(i)))
  
  rk(0) := keyExp(mk(1) ^ mk(2) ^ mk(3) ^ CK(0), CK(0))
  rk(1) := keyExp(mk(2) ^ mk(3) ^ rk(0) ^ CK(1), CK(1))
  rk(2) := keyExp(mk(3) ^ rk(0) ^ rk(1) ^ CK(2), CK(2))
  rk(3) := keyExp(rk(0) ^ rk(1) ^ rk(2) ^ CK(3), CK(3))
  
  for (i <- 4 until 32) {
    rk(i) := keyExp(rk(i-1) ^ rk(i-2) ^ rk(i-3) ^ CK(i % CK.length), CK(i % CK.length))
  }

  // -------------------- 4. 加解密轮密钥选择 --------------------
  val rk_sel = Wire(Vec(32, UInt(32.W)))
  for (i <- 0 until 32) {
    rk_sel(i) := Mux(io.mode, rk(31 - i), rk(i))
  }

  // -------------------- 5. CTR模式IV管理 --------------------
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

  // -------------------- 6. 4周期流水线加解密核心 --------------------
  val pipe_x = VecInit(Seq.fill(4)(RegInit(VecInit(Seq.fill(4)(0.U(32.W))))))
  val pipe_valid = VecInit(Seq.fill(5)(RegInit(false.B)))

  // 输入阶段
  when(io.en) {
    pipe_x(0)(0) := io.plaintext(31, 0)
    pipe_x(0)(1) := io.plaintext(63, 32)
    pipe_x(0)(2) := io.plaintext(95, 64)
    pipe_x(0)(3) := io.plaintext(127, 96)
    pipe_valid(0) := true.B
  }.otherwise {
    pipe_valid(0) := false.B
  }

  // 第1级：0-7轮
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

  // 第2级：8-15轮
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

  // 第3级：16-23轮
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

  // 第4级：24-31轮
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

  // 生成掩码
  val mask = Cat(x_stage4(11), x_stage4(10), x_stage4(9), x_stage4(8))

  // 输出处理
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

// ==================== 2. 寄存器定义 ====================
object DmaSM4PipelineRegs {
  // 基础寄存器
  val SRC_ADDR   = 0x00
  val DST_ADDR   = 0x04
  val LENGTH     = 0x08
  // CTRL寄存器：bit0=启动, bit1=完成, bit2=错误, bit3=加解密使能, bit4=padding使能, bit5=加解密模式(0=加密,1=解密)
  val CTRL       = 0x0C
  val STATUS     = 0x10
  
  // SM4配置寄存器
  val SM4_KEY0   = 0x14
  val SM4_KEY1   = 0x18
  val SM4_KEY2   = 0x1C
  val SM4_KEY3   = 0x20
  val SM4_IV0    = 0x24
  val SM4_IV1    = 0x28
  val SM4_IV2    = 0x2C
  val SM4_IV3    = 0x30

  // 地址解码
  val SRC_ADDR_SEL = (SRC_ADDR).U(32.W)(5, 2)
  val DST_ADDR_SEL = (DST_ADDR).U(32.W)(5, 2)
  val LENGTH_SEL   = (LENGTH).U(32.W)(5, 2)
  val CTRL_SEL     = (CTRL).U(32.W)(5, 2)
  val STATUS_SEL   = (STATUS).U(32.W)(5, 2)
  val SM4_KEY0_SEL = (SM4_KEY0).U(32.W)(5, 2)
  val SM4_KEY1_SEL = (SM4_KEY1).U(32.W)(5, 2)
  val SM4_KEY2_SEL = (SM4_KEY2).U(32.W)(5, 2)
  val SM4_KEY3_SEL = (SM4_KEY3).U(32.W)(5, 2)
  val SM4_IV0_SEL  = (SM4_IV0).U(32.W)(5, 2)
  val SM4_IV1_SEL  = (SM4_IV1).U(32.W)(5, 2)
  val SM4_IV2_SEL  = (SM4_IV2).U(32.W)(5, 2)
  val SM4_IV3_SEL  = (SM4_IV3).U(32.W)(5, 2)
}

// ==================== 3. 工具类 ====================
object DmaSM4PipelineUtils {
  // 安全burst长度计算
  def getSafeBurstLen(startAddr: UInt, remaining: UInt, beatBytes: Int = 32): UInt = {
    val pageMask = 0xFFF.U(32.W)
    val offset = startAddr & pageMask
    val bytesToPageEnd = Mux(offset === 0.U, 4096.U, (4096.U - offset) & pageMask)
    
    val maxInPage = bytesToPageEnd / beatBytes.U
    val maxByRemain = remaining / beatBytes.U
    val safeLen = Mux(maxInPage > 0.U, Mux(maxInPage < maxByRemain, maxInPage, maxByRemain), 1.U)
    Mux(safeLen > 15.U, 15.U, safeLen)
  }

  // 32字节对齐
  def alignTo32Byte(addr: UInt): UInt = (addr >> 5) << 5

  // PKCS#7 Padding补位
  def pkcs7Padding(data: UInt, validBytes: UInt): UInt = {
    val padLen = 16.U - validBytes
    val padValue = Fill(8, padLen)(7, 0)
    
    val paddedData = MuxLookup(validBytes, 0.U(128.W))(Seq(
      1.U  -> Cat(Fill(15, padValue), data(7, 0)),
      2.U  -> Cat(Fill(14, padValue), data(15, 0)),
      3.U  -> Cat(Fill(13, padValue), data(23, 0)),
      4.U  -> Cat(Fill(12, padValue), data(31, 0)),
      5.U  -> Cat(Fill(11, padValue), data(39, 0)),
      6.U  -> Cat(Fill(10, padValue), data(47, 0)),
      7.U  -> Cat(Fill(9, padValue), data(55, 0)),
      8.U  -> Cat(Fill(8, padValue), data(63, 0)),
      9.U  -> Cat(Fill(7, padValue), data(71, 0)),
      10.U -> Cat(Fill(6, padValue), data(79, 0)),
      11.U -> Cat(Fill(5, padValue), data(87, 0)),
      12.U -> Cat(Fill(4, padValue), data(95, 0)),
      13.U -> Cat(Fill(3, padValue), data(103, 0)),
      14.U -> Cat(Fill(2, padValue), data(111, 0)),
      15.U -> Cat(Fill(1, padValue), data(119, 0)),
      16.U -> data
    ))
    paddedData
  }

  // PKCS#7 Padding去补位
  def pkcs7Unpadding(data: UInt): (UInt, UInt) = {
    val padLen = data(7, 0)
    val padValid = padLen >= 1.U && padLen <= 16.U
    val validData = MuxLookup(padLen, data)(Seq(
      1.U  -> Cat(0.U(120.W), data(127, 120)),
      2.U  -> Cat(0.U(112.W), data(127, 112)),
      3.U  -> Cat(0.U(104.W), data(127, 104)),
      4.U  -> Cat(0.U(96.W), data(127, 96)),
      5.U  -> Cat(0.U(88.W), data(127, 88)),
      6.U  -> Cat(0.U(80.W), data(127, 80)),
      7.U  -> Cat(0.U(72.W), data(127, 72)),
      8.U  -> Cat(0.U(64.W), data(127, 64)),
      9.U  -> Cat(0.U(56.W), data(127, 56)),
      10.U -> Cat(0.U(48.W), data(127, 48)),
      11.U -> Cat(0.U(40.W), data(127, 40)),
      12.U -> Cat(0.U(32.W), data(127, 32)),
      13.U -> Cat(0.U(24.W), data(127, 24)),
      14.U -> Cat(0.U(16.W), data(127, 16)),
      15.U -> Cat(0.U(8.W), data(127, 8)),
      16.U -> 0.U(128.W)
    ))
    val validBytes = 16.U - Mux(padValid, padLen, 0.U)
    (validData, validBytes)
  }
}
/*
// ==================== 4. APB4接口 ====================
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

// ==================== 5. AXI4接口 ====================
class AXI4Intf extends Bundle {
  // 读地址通道
  val ar = new Bundle {
    val araddr  = Output(UInt(32.W))
    val arburst = Output(UInt(2.W))
    val arsize  = Output(UInt(3.W))
    val arlen   = Output(UInt(8.W))
    val arvalid = Output(Bool())
    val arready = Input(Bool())
  }
  
  // 读数据通道
  val r = new Bundle {
    val rdata  = Input(UInt(256.W))
    val rresp  = Input(UInt(2.W))
    val rlast  = Input(Bool())
    val rvalid = Input(Bool())
    val rready = Output(Bool())
  }
  
  // 写地址通道
  val aw = new Bundle {
    val awaddr  = Output(UInt(32.W))
    val awburst = Output(UInt(2.W))
    val awsize  = Output(UInt(3.W))
    val awlen   = Output(UInt(8.W))
    val awvalid = Output(Bool())
    val awready = Input(Bool())
  }
  
  // 写数据通道
  val w = new Bundle {
    val wdata  = Output(UInt(256.W))
    val wstrb  = Output(UInt(32.W))
    val wlast  = Output(Bool())
    val wvalid = Output(Bool())
    val wready = Input(Bool())
  }
  
  // 写响应通道
  val b = new Bundle {
    val bresp  = Input(UInt(2.W))
    val bvalid = Input(Bool())
    val bready = Output(Bool())
  }
}
*/
// ==================== 6. DMA+SM4加解密控制器 ====================
class DMAControllerWithSM4Pipeline(
  readFifoDepth: Int = 32,
  cryptoFifoDepth: Int = 32,
  burstBeatBytes: Int = 32,
  maxBurstLen: Int = 15
) extends Module {
  val io = IO(new Bundle {
    val apb  = new APB4IO()
    val axi  = new AXI4Intf()
    val busy = Output(Bool())
    val level = Output(UInt(8.W))
  })

  // -------------------- 1. 全局状态与寄存器 --------------------
  val sIdle :: sRunning :: sPadding :: sUnpadding :: sDone :: sError :: Nil = Enum(6)
  val globalState = RegInit(sIdle)

  // 配置寄存器
  val regSrcAddr  = RegInit(0.U(32.W))
  val regDstAddr  = RegInit(0.U(32.W))
  val regTotalLen = RegInit(0.U(32.W))
  val regCtrl     = RegInit(0.U(32.W))
  val regStatus   = RegInit(0.U(32.W))
  
  // SM4配置寄存器
  val regSM4Key   = RegInit(VecInit(Seq.fill(4)(0.U(32.W))))
  val regSM4IV    = RegInit(VecInit(Seq.fill(4)(0.U(32.W))))

  // 传输状态
  val remainBytes = RegInit(0.U(32.W))
  val totalProcessed = RegInit(0.U(32.W))
  val lastBlockValidBytes = RegInit(0.U(4.W))
  val unpaddingValidBytes = RegInit(0.U(4.W))

  // -------------------- 2. APB接口 --------------------
  val apbSel = Wire(UInt(4.W))
  apbSel := io.apb.PADDR(5, 2)

  io.apb.PREADY  := true.B
  io.apb.PSLVERR := false.B
  io.apb.PRDATA  := 0.U

  // APB读
  when(io.apb.PSEL && !io.apb.PWRITE && io.apb.PENABLE) {
    switch(apbSel) {
      is(DmaSM4PipelineRegs.SRC_ADDR_SEL)  { io.apb.PRDATA := regSrcAddr }
      is(DmaSM4PipelineRegs.DST_ADDR_SEL)  { io.apb.PRDATA := regDstAddr }
      is(DmaSM4PipelineRegs.LENGTH_SEL)    { io.apb.PRDATA := regTotalLen }
      is(DmaSM4PipelineRegs.CTRL_SEL)      { io.apb.PRDATA := regCtrl }
      is(DmaSM4PipelineRegs.STATUS_SEL)    { io.apb.PRDATA := regStatus }
      is(DmaSM4PipelineRegs.SM4_KEY0_SEL)  { io.apb.PRDATA := regSM4Key(0) }
      is(DmaSM4PipelineRegs.SM4_KEY1_SEL)  { io.apb.PRDATA := regSM4Key(1) }
      is(DmaSM4PipelineRegs.SM4_KEY2_SEL)  { io.apb.PRDATA := regSM4Key(2) }
      is(DmaSM4PipelineRegs.SM4_KEY3_SEL)  { io.apb.PRDATA := regSM4Key(3) }
      is(DmaSM4PipelineRegs.SM4_IV0_SEL)   { io.apb.PRDATA := regSM4IV(0) }
      is(DmaSM4PipelineRegs.SM4_IV1_SEL)   { io.apb.PRDATA := regSM4IV(1) }
      is(DmaSM4PipelineRegs.SM4_IV2_SEL)   { io.apb.PRDATA := regSM4IV(2) }
      is(DmaSM4PipelineRegs.SM4_IV3_SEL)   { io.apb.PRDATA := regSM4IV(3) }
    }
  }

  // APB写
  when(io.apb.PSEL && io.apb.PWRITE && io.apb.PENABLE && !regStatus(0)) {
    switch(apbSel) {
      is(DmaSM4PipelineRegs.SRC_ADDR_SEL)  { regSrcAddr := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.DST_ADDR_SEL)  { regDstAddr := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.LENGTH_SEL)    { regTotalLen := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.CTRL_SEL)      {
        val clearMask = ~((1.U << 1) | (1.U << 2)).asUInt
        regCtrl := io.apb.PWDATA & clearMask
      }
      is(DmaSM4PipelineRegs.SM4_KEY0_SEL)  { regSM4Key(0) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_KEY1_SEL)  { regSM4Key(1) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_KEY2_SEL)  { regSM4Key(2) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_KEY3_SEL)  { regSM4Key(3) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_IV0_SEL)   { regSM4IV(0) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_IV1_SEL)   { regSM4IV(1) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_IV2_SEL)   { regSM4IV(2) := io.apb.PWDATA }
      is(DmaSM4PipelineRegs.SM4_IV3_SEL)   { regSM4IV(3) := io.apb.PWDATA }
    }
  }

  // -------------------- 3. 流水线FIFO --------------------
  val readFifo = Module(new Queue(UInt(128.W), readFifoDepth, pipe = true, flow = true))
  readFifo.io.enq.valid := false.B
  readFifo.io.enq.bits  := 0.U

  val cryptoFifo = Module(new Queue(UInt(128.W), cryptoFifoDepth, pipe = true, flow = true))
  cryptoFifo.io.enq.valid := false.B
  cryptoFifo.io.enq.bits  := 0.U
  cryptoFifo.io.deq.ready := false.B

  io.level := Cat(readFifo.io.count, cryptoFifo.io.count)(7, 0)

  // -------------------- 4. AXI读 --------------------
  val sRIdle :: sRSetup :: sRData :: Nil = Enum(3)
  val readState = RegInit(sRIdle)
  
  val readAddr   = RegInit(0.U(32.W))
  val readBurst  = RegInit(0.U(4.W))
  val readBeatCnt = RegInit(0.U(4.W))
  
  io.axi.ar.araddr  := 0.U
  io.axi.ar.arburst := 1.U
  io.axi.ar.arsize  := 5.U
  io.axi.ar.arlen   := 0.U
  io.axi.ar.arvalid := false.B
  io.axi.r.rready   := false.B

  switch(readState) {
    is(sRIdle) {
      when(globalState === sRunning && readFifo.io.count < (readFifoDepth - 4).U) {
        readAddr := Mux(readAddr === 0.U, regSrcAddr, readAddr)
        readState := sRSetup
      }
    }

    is(sRSetup) {
      val safeLen = DmaSM4PipelineUtils.getSafeBurstLen(readAddr, remainBytes, burstBeatBytes)
      readBurst := Mux(safeLen > maxBurstLen.U, maxBurstLen.U, safeLen)
      
      io.axi.ar.araddr  := readAddr
      io.axi.ar.arlen   := readBurst - 1.U
      io.axi.ar.arvalid := true.B

      when(io.axi.ar.arready) {
        io.axi.ar.arvalid := false.B
        readBeatCnt := 0.U
        readState := sRData
        io.axi.r.rready := true.B
      }
    }

    is(sRData) {
      io.axi.r.rready := true.B
      
      when(io.axi.r.rvalid) {
        val data_32b = io.axi.r.rdata
        val data1_128b = data_32b(127, 0)
        val data2_128b = data_32b(255, 128)
        
        val bytesToRead = Mux(remainBytes >= 32.U, 32.U, remainBytes)
        when(bytesToRead >= 16.U) {
          readFifo.io.enq.valid := true.B
          readFifo.io.enq.bits := data1_128b
          remainBytes := remainBytes - 16.U
          
          when(bytesToRead > 16.U) {
            val readFifoEn2 = Wire(Bool())
            readFifoEn2 := readFifo.io.enq.fire && (bytesToRead > 16.U)
            when(readFifoEn2) {
              readFifo.io.enq.bits := data2_128b
              remainBytes := remainBytes - 16.U
            }
          }.otherwise {
            lastBlockValidBytes := 16.U
          }
        }.otherwise {
          lastBlockValidBytes := bytesToRead(3, 0)
          val partialData = MuxLookup(bytesToRead, 0.U(128.W))(Seq(
            1.U  -> Cat(0.U(120.W), data_32b(7, 0)),
            2.U  -> Cat(0.U(112.W), data_32b(15, 0)),
            3.U  -> Cat(0.U(104.W), data_32b(23, 0)),
            4.U  -> Cat(0.U(96.W), data_32b(31, 0)),
            5.U  -> Cat(0.U(88.W), data_32b(39, 0)),
            6.U  -> Cat(0.U(80.W), data_32b(47, 0)),
            7.U  -> Cat(0.U(72.W), data_32b(55, 0)),
            8.U  -> Cat(0.U(64.W), data_32b(63, 0)),
            9.U  -> Cat(0.U(56.W), data_32b(71, 0)),
            10.U -> Cat(0.U(48.W), data_32b(79, 0)),
            11.U -> Cat(0.U(40.W), data_32b(87, 0)),
            12.U -> Cat(0.U(32.W), data_32b(95, 0)),
            13.U -> Cat(0.U(24.W), data_32b(103, 0)),
            14.U -> Cat(0.U(16.W), data_32b(111, 0)),
            15.U -> Cat(0.U(8.W), data_32b(119, 0))
          ))
          readFifo.io.enq.valid := true.B
          readFifo.io.enq.bits := partialData
          remainBytes := 0.U
        }
        
        readBeatCnt := readBeatCnt + 1.U
        readAddr := DmaSM4PipelineUtils.alignTo32Byte(readAddr + burstBeatBytes.U)

        val burstEnd = io.axi.r.rlast || (readBeatCnt === readBurst) || (remainBytes === 0.U)
        when(burstEnd) {
          io.axi.r.rready := false.B
          readState := Mux(globalState === sRunning && remainBytes > 0.U, sRSetup, sRIdle)
          
          when(remainBytes === 0.U) {
            globalState := Mux(regCtrl(5), sUnpadding, sPadding)
          }
        }
      }
    }
  }

  // -------------------- 5. SM4加解密 --------------------
  val sm4 = Module(new SM4Pipeline_4Cycle())
  sm4.io.en := false.B
  sm4.io.reset_iv := (globalState === sIdle)
  sm4.io.mode := regCtrl(5)
  sm4.io.key := regSM4Key
  sm4.io.init_iv := regSM4IV
  sm4.io.plaintext := 0.U(128.W)

  val cryptoTrigger = (readFifo.io.deq.valid && cryptoFifo.io.count < (cryptoFifoDepth - 1).U && regCtrl(3))
  val paddingTrigger = (globalState === sPadding && readFifo.io.deq.valid)
  val unpaddingTrigger = (globalState === sUnpadding && readFifo.io.deq.valid)

  when(cryptoTrigger || paddingTrigger || unpaddingTrigger) {
    readFifo.io.deq.ready := true.B
    
    val plaintext = Mux(globalState === sPadding,
      DmaSM4PipelineUtils.pkcs7Padding(readFifo.io.deq.bits, lastBlockValidBytes),
      readFifo.io.deq.bits
    )
    
    sm4.io.plaintext := plaintext
    sm4.io.en := true.B
    
    when(sm4.io.valid) {
      cryptoFifo.io.enq.valid := true.B
      
      val (unpaddedData, validBytes) = DmaSM4PipelineUtils.pkcs7Unpadding(sm4.io.ciphertext)
      cryptoFifo.io.enq.bits := Mux(globalState === sUnpadding, unpaddedData, sm4.io.ciphertext)
      
      when(globalState === sUnpadding) {
        unpaddingValidBytes := validBytes
      }
    }
  }.otherwise {
    readFifo.io.deq.ready := false.B
  }

  // -------------------- 6. AXI写 --------------------
  val sWIdle :: sWSetup :: sWData :: Nil = Enum(3)
  val writeState = RegInit(sWIdle)
  
  val writeAddr   = RegInit(0.U(32.W))
  val writeBurst  = RegInit(0.U(4.W))
  val writeBeatCnt = RegInit(0.U(4.W))
  val writeDataReg = RegInit(0.U(256.W))

  io.axi.aw.awaddr  := 0.U
  io.axi.aw.awburst := 1.U
  io.axi.aw.awsize  := 5.U
  io.axi.aw.awlen   := 0.U
  io.axi.aw.awvalid := false.B
  
  io.axi.w.wdata  := 0.U
  io.axi.w.wstrb  := Fill(32, 1.U(1.W))
  io.axi.w.wlast  := false.B
  io.axi.w.wvalid := false.B
  io.axi.b.bready := true.B

  val collect128bit = RegInit(false.B)
  val first128bit = RegInit(0.U(128.W))
  val isLastBlock = RegInit(false.B)

  switch(writeState) {
    is(sWIdle) {
      when(cryptoFifo.io.deq.valid && (globalState === sRunning || globalState === sPadding || globalState === sUnpadding)) {
        writeAddr := Mux(writeAddr === 0.U, regDstAddr, writeAddr)
        writeState := sWSetup
        collect128bit := false.B
        isLastBlock := (globalState === sPadding || globalState === sUnpadding)
      }
    }

    is(sWSetup) {
      val fifoCount = cryptoFifo.io.count
      val burstLen = Mux(fifoCount >= 2.U, Mux(fifoCount > (maxBurstLen * 2).U, maxBurstLen.U, (fifoCount / 2.U)), 1.U)
      writeBurst := burstLen
      
      io.axi.aw.awaddr  := writeAddr
      io.axi.aw.awlen   := burstLen - 1.U
      io.axi.aw.awvalid := true.B

      when(io.axi.aw.awready) {
        io.axi.aw.awvalid := false.B
        writeBeatCnt := 0.U
        writeState := sWData
      }
    }

    is(sWData) {
      when(cryptoFifo.io.deq.valid && !collect128bit) {
        first128bit := cryptoFifo.io.deq.bits
        cryptoFifo.io.deq.ready := true.B
        collect128bit := true.B
      }.elsewhen(cryptoFifo.io.deq.valid && collect128bit) {
        writeDataReg := Cat(cryptoFifo.io.deq.bits, first128bit)
        cryptoFifo.io.deq.ready := true.B
        collect128bit := false.B
        
        io.axi.w.wdata  := writeDataReg
        io.axi.w.wvalid := true.B
        io.axi.w.wlast  := (writeBeatCnt === writeBurst - 1.U) || (isLastBlock && unpaddingValidBytes < 16.U)

        when(isLastBlock && regCtrl(5) && unpaddingValidBytes < 16.U) {
          val wstrb = MuxLookup(unpaddingValidBytes, Fill(32, 1.U(1.W)))(Seq(
            1.U  -> Cat(Fill(31, 0.U(1.W)), 1.U(1.W)),
            2.U  -> Cat(Fill(30, 0.U(1.W)), Fill(2, 1.U(1.W))),
            3.U  -> Cat(Fill(29, 0.U(1.W)), Fill(3, 1.U(1.W))),
            4.U  -> Cat(Fill(28, 0.U(1.W)), Fill(4, 1.U(1.W))),
            5.U  -> Cat(Fill(27, 0.U(1.W)), Fill(5, 1.U(1.W))),
            6.U  -> Cat(Fill(26, 0.U(1.W)), Fill(6, 1.U(1.W))),
            7.U  -> Cat(Fill(25, 0.U(1.W)), Fill(7, 1.U(1.W))),
            8.U  -> Cat(Fill(24, 0.U(1.W)), Fill(8, 1.U(1.W))),
            9.U  -> Cat(Fill(23, 0.U(1.W)), Fill(9, 1.U(1.W))),
            10.U -> Cat(Fill(22, 0.U(1.W)), Fill(10, 1.U(1.W))),
            11.U -> Cat(Fill(21, 0.U(1.W)), Fill(11, 1.U(1.W))),
            12.U -> Cat(Fill(20, 0.U(1.W)), Fill(12, 1.U(1.W))),
            13.U -> Cat(Fill(19, 0.U(1.W)), Fill(13, 1.U(1.W))),
            14.U -> Cat(Fill(18, 0.U(1.W)), Fill(14, 1.U(1.W))),
            15.U -> Cat(Fill(17, 0.U(1.W)), Fill(15, 1.U(1.W)))
          ))
          io.axi.w.wstrb := wstrb
        }

        when(io.axi.w.wready) {
          writeBeatCnt := writeBeatCnt + 1.U
          writeAddr := DmaSM4PipelineUtils.alignTo32Byte(writeAddr + burstBeatBytes.U)
          totalProcessed := totalProcessed + 32.U

          val burstEnd = io.axi.w.wlast || (cryptoFifo.io.count === 0.U && globalState === sDone)
          when(burstEnd) {
            io.axi.w.wvalid := false.B
            writeState := Mux(cryptoFifo.io.deq.valid && (globalState === sRunning || globalState === sPadding || globalState === sUnpadding), sWSetup, sWIdle)
            
            when(cryptoFifo.io.count === 0.U && (globalState === sPadding || globalState === sUnpadding)) {
              globalState := sDone
            }
          }
        }
      }
    }
  }

  // -------------------- 7. 全局状态机 --------------------
  switch(globalState) {
    is(sIdle) {
      when(regCtrl(0) && !regStatus(0)) {
        when(regTotalLen === 0.U) {
          regCtrl := regCtrl | (1.U << 1)
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

    is(sRunning) {
      when((io.axi.b.bvalid && io.axi.b.bresp =/= 0.U) || (io.axi.r.rvalid && io.axi.r.rresp =/= 0.U)) {
        regCtrl := regCtrl | (1.U << 2)
        globalState := sError
      }
    }

    is(sPadding) {
      when(cryptoFifo.io.count === 0.U && writeState === sWIdle) {
        globalState := sDone
      }
    }

    is(sUnpadding) {
      when(cryptoFifo.io.count === 0.U && writeState === sWIdle) {
        globalState := sDone
      }
    }

    is(sDone) {
      regCtrl := regCtrl | (1.U << 1)
      regCtrl := regCtrl & ~(1.U << 0)
      globalState := sIdle
    }

    is(sError) {
      regCtrl := regCtrl | (1.U << 2)
      regCtrl := regCtrl & ~(1.U << 0)
      remainBytes := 0.U
      totalProcessed := 0.U
      globalState := sIdle
    }
  }

  // 状态寄存器更新
  regStatus := Cat(
    (globalState === sError),
    (globalState === sDone),
    (globalState === sUnpadding),
    (globalState === sPadding),
    (globalState === sRunning)
  )

  io.busy := (globalState === sRunning) || (globalState === sPadding) || (globalState === sUnpadding)
}

// ==================== 7. 生成器 ====================
object DMAGenWithSM4 extends App {
  println("Generating Pipelined DMA Controller with SM4 CTR Encryption/Decryption...")
  
  _root_.circt.stage.ChiselStage.emitSystemVerilogFile(
    new DMAControllerWithSM4Pipeline(
      readFifoDepth = 32,
      cryptoFifoDepth = 32,
      maxBurstLen = 15
    ),
    Array(
      "--target-dir=output_dma_sm4_crypto"
    )
  )
}