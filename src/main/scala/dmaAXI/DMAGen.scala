package dmaAXI

// Use CIRCT-backed ChiselStage available in this project to emit SystemVerilog
object DMAGen extends App {
  println("Generating AXI DMA Controller SystemVerilog...")
  _root_.circt.stage.ChiselStage.emitSystemVerilogFile(
    new DMAController(),
    Array(
      "--target-dir=outputDMAController"
    ),
    firtoolOpts = Array("-disable-all-randomization",  "-default-layer-specialization=enable")     
  )
}

