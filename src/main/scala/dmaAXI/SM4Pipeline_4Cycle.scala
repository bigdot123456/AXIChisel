package dmaAXI

import chisel3._
import chisel3.util._

// ==================== 4周期流水线SM4加密模块（适配AXI 16byte读取） ====================
class SM4Pipeline_4Cycle_err extends Module {
  val io = IO(new Bundle {
    // 控制信号
    val en = Input(Bool())        // 加密使能（输入数据有效时置位）
    val reset_iv = Input(Bool())  // 重置IV为初始值
    
    // 配置接口
    val key = Input(Vec(4, UInt(32.W)))  // 128bit SM4密钥
    val init_iv = Input(Vec(4, UInt(32.W))) // 128bit初始IV
    
    // 数据接口（128bit粒度）
    val plaintext = Input(UInt(128.W))   // 输入明文（128bit）
    val ciphertext = Output(UInt(128.W)) // 输出密文（128bit）
    val valid = Output(Bool())           // 加密完成有效（4周期后置位）
    val iv_out = Output(Vec(4, UInt(32.W))) // 输出当前IV
  })

  // -------------------- 1. SM4基础定义（复用原有） --------------------
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

  // -------------------- 2. SM4核心函数（复用原有） --------------------
  def sboxSub(in: UInt): UInt = {
    val bytes = VecInit((0 to 3).map(i => in(8*(3-i)+7, 8*(3-i))))
    VecInit(bytes.map(b => SBOX(b))).asUInt
  }

  def rotl(in: UInt, n: Int): UInt = (in << n) | (in >> (32 - n))
  def ltrans(in: UInt): UInt = in ^ rotl(in, 2) ^ rotl(in, 10) ^ rotl(in, 18) ^ rotl(in, 24)
  def ttrans(in: UInt): UInt = ltrans(sboxSub(in))
  def keyExp(in: UInt, ck: UInt): UInt = in ^ ttrans(in ^ rotl(in, 13) ^ rotl(in, 23) ^ ck)

  // -------------------- 3. 密钥扩展（预计算，仅一次） --------------------
  val rk = VecInit(Seq.fill(32)(0.U(32.W)))
  val mk = VecInit((0 to 3).map(i => io.key(i) ^ FK(i)))
  
  rk(0) := keyExp(mk(1) ^ mk(2) ^ mk(3) ^ CK(0), CK(0))
  rk(1) := keyExp(mk(2) ^ mk(3) ^ rk(0) ^ CK(1), CK(1))
  rk(2) := keyExp(mk(3) ^ rk(0) ^ rk(1) ^ CK(2), CK(2))
  rk(3) := keyExp(rk(0) ^ rk(1) ^ rk(2) ^ CK(3), CK(3))
  
  for (i <- 4 until 32) {
    rk(i) := keyExp(rk(i-1) ^ rk(i-2) ^ rk(i-3) ^ CK(i % CK.length), CK(i % CK.length))
  }

  // -------------------- 4. CTR模式IV管理（复用原有） --------------------
  val iv_reg = RegInit(VecInit(Seq.fill(4)(0.U(32.W))))
  when(io.reset_iv) {
    iv_reg := io.init_iv
  }.elsewhen(io.en) {
    // IV自增（128bit）
    val iv_128 = Cat(iv_reg(3), iv_reg(2), iv_reg(1), iv_reg(0))
    val iv_inc = iv_128 + 1.U(128.W)
    iv_reg(0) := iv_inc(31, 0)
    iv_reg(1) := iv_inc(63, 32)
    iv_reg(2) := iv_inc(95, 64)
    iv_reg(3) := iv_inc(127, 96)
  }
  io.iv_out := iv_reg

  // -------------------- 5. 4周期流水线加密核心（关键修改） --------------------
  // 步骤1：将32轮拆分为4级流水线，每级8轮
  // 定义流水线寄存器（保存每级的中间结果）
  val pipe_regs = VecInit(Seq.fill(4)(RegInit(VecInit(Seq.fill(4)(0.U(32.W))))))
  // 流水线有效信号（跟踪每级的输入是否有效）
  val pipe_valid = VecInit(Seq.fill(5)(RegInit(false.B))) // 5个阶段：输入+4级流水线

  // 步骤2：输入阶段（周期1）
  when(io.en) {
    // 初始输入：明文拆分为4个32bit字
    pipe_regs(0)(0) := io.plaintext(31, 0)
    pipe_regs(0)(1) := io.plaintext(63, 32)
    pipe_regs(0)(2) := io.plaintext(95, 64)
    pipe_regs(0)(3) := io.plaintext(127, 96)
    pipe_valid(0) := true.B
  }.otherwise {
    pipe_valid(0) := false.B
  }

  // 步骤3：4级流水线计算（每级8轮）
  // 第1级：0-7轮
  val x1 = VecInit(Seq.fill(12)(0.U(32.W))) // 0-11轮，初始4个+8轮
  x1(0) := pipe_regs(0)(0)
  x1(1) := pipe_regs(0)(1)
  x1(2) := pipe_regs(0)(2)
  x1(3) := pipe_regs(0)(3)
  for (i <- 0 until 8) {
    x1(i+4) := x1(i) ^ ttrans(x1(i+1) ^ x1(i+2) ^ x1(i+3) ^ rk(i))
  }
  // 保存到第2级寄存器
  pipe_regs(1)(0) := x1(8)
  pipe_regs(1)(1) := x1(9)
  pipe_regs(1)(2) := x1(10)
  pipe_regs(1)(3) := x1(11)
  pipe_valid(1) := pipe_valid(0)

  // 第2级：8-15轮
  val x2 = VecInit(Seq.fill(12)(0.U(32.W))) // 8-19轮
  x2(0) := pipe_regs(1)(0)
  x2(1) := pipe_regs(1)(1)
  x2(2) := pipe_regs(1)(2)
  x2(3) := pipe_regs(1)(3)
  for (i <- 8 until 16) {
    x2((i-8)+4) := x2(i-8) ^ ttrans(x2((i-8)+1) ^ x2((i-8)+2) ^ x2((i-8)+3) ^ rk(i))
  }
  // 保存到第3级寄存器
  pipe_regs(2)(0) := x2(8)
  pipe_regs(2)(1) := x2(9)
  pipe_regs(2)(2) := x2(10)
  pipe_regs(2)(3) := x2(11)
  pipe_valid(2) := pipe_valid(1)

  // 第3级：16-23轮
  val x3 = VecInit(Seq.fill(12)(0.U(32.W))) // 16-27轮
  x3(0) := pipe_regs(2)(0)
  x3(1) := pipe_regs(2)(1)
  x3(2) := pipe_regs(2)(2)
  x3(3) := pipe_regs(2)(3)
  for (i <- 16 until 24) {
    x3((i-16)+4) := x3(i-16) ^ ttrans(x3((i-16)+1) ^ x3((i-16)+2) ^ x3((i-16)+3) ^ rk(i))
  }
  // 保存到第4级寄存器
  pipe_regs(3)(0) := x3(8)
  pipe_regs(3)(1) := x3(9)
  pipe_regs(3)(2) := x3(10)
  pipe_regs(3)(3) := x3(11)
  pipe_valid(3) := pipe_valid(2)

  // 第4级：24-31轮
  val x4 = VecInit(Seq.fill(12)(0.U(32.W))) // 24-35轮
  x4(0) := pipe_regs(3)(0)
  x4(1) := pipe_regs(3)(1)
  x4(2) := pipe_regs(3)(2)
  x4(3) := pipe_regs(3)(3)
  for (i <- 24 until 32) {
    x4((i-24)+4) := x4(i-24) ^ ttrans(x4((i-24)+1) ^ x4((i-24)+2) ^ x4((i-24)+3) ^ rk(i))
  }
  pipe_valid(4) := pipe_valid(3)

  // 步骤4：输出处理（CTR模式）
  val mask = Cat(x4(35), x4(34), x4(33), x4(32)) // 32轮后的掩码
  val ciphertext_reg = RegInit(0.U(128.W))
  val valid_reg = RegInit(false.B)

  // 4周期后输出有效
  when(pipe_valid(4)) {
    // CTR模式：明文 ^ 掩码
    ciphertext_reg := io.plaintext ^ mask
    valid_reg := true.B
  }.otherwise {
    valid_reg := false.B
  }

  // 最终输出
  io.ciphertext := ciphertext_reg
  io.valid := valid_reg
}

// ==================== 6. 集成到原有DMA控制器（替换原SM4模块） ====================
// 在DMAControllerWithSM4Pipeline中，将：
// val sm4 = Module(new SM4CTR_128())
// 替换为：
// val sm4 = Module(new SM4Pipeline_4Cycle())