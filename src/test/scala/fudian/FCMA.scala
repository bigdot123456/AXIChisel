package fudian

// Use CIRCT ChiselStage available in this repo
object FCMAMain extends App {
  _root_.circt.stage.ChiselStage.emitSystemVerilogFile(new FCMA(11, 53))
}
