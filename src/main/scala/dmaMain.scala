// Top-level runner expected by `mill dmaAXI.runMain dmaMain`
object dmaMain {
  def main(args: Array[String]): Unit = {
    println("dmaMain: invoking dmaAXI.DMAGen...")
    try {
      dmaAXI.DMAGen.main(args)
    } catch {
      case e: Throwable =>
        println(s"dmaMain: failed to invoke DMAGen: ${e.getMessage}")
        throw e
    }
  }
}
