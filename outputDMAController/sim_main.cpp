#include "verilated.h"
#include "VDmaSM4SGTop.h"
#include <iostream>
#if VM_TRACE
#include "verilated_vcd_c.h"
#endif

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    VDmaSM4SGTop* top = new VDmaSM4SGTop;

    // initialize
    top->clock = 0;
    top->reset = 1;
    top->io_apb_PADDR = 0;
    top->io_apb_PPROT = 0;
    top->io_apb_PSEL = 0;
    top->io_apb_PENABLE = 0;
    top->io_apb_PWRITE = 0;
    top->io_apb_PWDATA = 0;
    top->io_apb_PSTRB = 0;

    // AXI inputs
    top->io_axi_arready = 0;
    // io_axi_rdata is a wide (256-bit) input; set all 32-bit words to 0
    for (int i = 0; i < 8; ++i) top->io_axi_rdata[i] = 0;
    top->io_axi_rresp = 0;
    top->io_axi_rlast = 0;
    top->io_axi_rvalid = 0;
    top->io_axi_awready = 0;
    top->io_axi_wready = 0;
    top->io_axi_bresp = 0;
    top->io_axi_bvalid = 0;
    // AXI slave internal state
    uint64_t axi_araddr = 0;
    unsigned axi_arlen = 0;
    unsigned axi_arbeats = 0;
    unsigned axi_arbeat_ix = 0;
    bool axi_read_active = false;
    uint64_t axi_awaddr = 0;
    unsigned axi_awlen = 0;
    unsigned axi_awbeats = 0;
    unsigned axi_awbeat_ix = 0;
    bool axi_write_active = false;

    // enable tracing (only if verilator compiled with trace support)
#if VM_TRACE
    Verilated::traceEverOn(true);
    VerilatedVcdC* tfp = nullptr;
    tfp = new VerilatedVcdC;
    top->trace(tfp, 5);
    tfp->open("sim.vcd");
#endif

    for (int i = 0; i < 5; ++i) {
        top->clock = !top->clock; top->eval();
    #if VM_TRACE
        if (tfp) tfp->dump(i);
    #endif
    }

    // release reset
    top->reset = 0;
        // helper: APB write (simple single-beat sequence)
        auto apb_write = [&](uint32_t addr, uint32_t data) {
        top->io_apb_PADDR = addr;
        top->io_apb_PWDATA = data;
        top->io_apb_PWRITE = 1;
        top->io_apb_PSEL = 1;
        top->io_apb_PENABLE = 0;
        top->clock = !top->clock; top->eval();
    #if VM_TRACE
        if (tfp) tfp->dump(0);
    #endif
        top->io_apb_PENABLE = 1;
        top->clock = !top->clock; top->eval();
    #if VM_TRACE
        if (tfp) tfp->dump(1);
    #endif
        top->io_apb_PSEL = 0;
        top->io_apb_PENABLE = 0;
        top->io_apb_PWRITE = 0;
        };

            // helper: APB read (single-beat)
            auto apb_read = [&](uint32_t addr)->uint32_t {
            top->io_apb_PADDR = addr;
            top->io_apb_PWRITE = 0;
            top->io_apb_PSEL = 1;
            top->io_apb_PENABLE = 0;
            top->clock = !top->clock; top->eval();
        #if VM_TRACE
            if (tfp) tfp->dump(0);
        #endif
            top->io_apb_PENABLE = 1;
            top->clock = !top->clock; top->eval();
        #if VM_TRACE
            if (tfp) tfp->dump(1);
        #endif
            uint32_t val = (uint32_t)top->io_apb_PRDATA;
            top->io_apb_PSEL = 0;
            top->io_apb_PENABLE = 0;
            return val;
            };

        // perform APB sequences: first a 64-byte transfer (no crypto),
        // then a 48-byte transfer with crypto enabled
        apb_write(0x00, 0x1000); // REG_SRC_ADDR
        apb_write(0x04, 0x2000); // REG_DST_ADDR
        apb_write(0x08, 64);     // REG_LENGTH (bytes)
        apb_write(0x0C, 1);      // REG_CTRL: start

        // small delay between operations
        for (int d = 0; d < 4; ++d) { top->clock = !top->clock; top->eval(); }

        // second transfer: enable crypto mode in CTRL (bit 3 = crypto_en)
        apb_write(0x00, 0x3000); // REG_SRC_ADDR
        apb_write(0x04, 0x4000); // REG_DST_ADDR
        apb_write(0x08, 48);     // REG_LENGTH (bytes)
        apb_write(0x0C, (1U << 3) | 1U); // start + crypto enable

        const int RUN_CYCLES = 10000;
        // Simulation main loop with a simple AXI slave implementation
        bool b_pending = false;
        bool prev_busy = (int)top->io_busy;
        for (int i = 0; i < RUN_CYCLES; ++i) {
            // Drive ready/valid inputs for AXI slave based on state
            top->io_axi_arready = !axi_read_active ? 1 : 0;
            top->io_axi_awready = !axi_write_active ? 1 : 0;
            top->io_axi_wready  = 1;

            // drive read data when active
            if (axi_read_active && (axi_arbeat_ix < axi_arbeats)) {
                // provide deterministic data: each 32-bit word = low32(address + beat*BEAT_BYTES + word*4)
                uint64_t base = axi_araddr + (uint64_t)axi_arbeat_ix * 32ULL;
                for (int w = 0; w < 8; ++w) {
                    top->io_axi_rdata[w] = (uint32_t)(base + w*4);
                }
                top->io_axi_rresp = 0;
                top->io_axi_rvalid = 1;
                top->io_axi_rlast = (axi_arbeat_ix + 1 == axi_arbeats) ? 1 : 0;
            } else {
                top->io_axi_rvalid = 0;
                top->io_axi_rlast = 0;
            }

            // drive write response when pending
            top->io_axi_bvalid = b_pending ? 1 : 0;
            top->io_axi_bresp = 0;

            // tick
            top->clock = !top->clock; top->eval();
    #if VM_TRACE
            if (tfp) tfp->dump(i+5);
    #endif

            // Sample DUT outputs and update AXI slave state
            // AR handshake
            if (top->io_axi_arvalid && top->io_axi_arready && !axi_read_active) {
                axi_araddr = (uint64_t)top->io_axi_araddr;
                axi_arlen = (unsigned)top->io_axi_arlen;
                axi_arbeats = axi_arlen + 1U;
                axi_arbeat_ix = 0;
                axi_read_active = true;
            }

            // R handshake: if we presented rvalid and DUT accepted (rready)
            if (axi_read_active && top->io_axi_rvalid && top->io_axi_rready) {
                axi_arbeat_ix++;
                if (axi_arbeat_ix >= axi_arbeats) {
                    axi_read_active = false;
                    top->io_axi_rvalid = 0;
                    top->io_axi_rlast = 0;
                }
            }

            // AW handshake
            if (top->io_axi_awvalid && top->io_axi_awready && !axi_write_active) {
                axi_awaddr = (uint64_t)top->io_axi_awaddr;
                axi_awlen = (unsigned)top->io_axi_awlen;
                axi_awbeats = axi_awlen + 1U;
                axi_awbeat_ix = 0;
                axi_write_active = true;
                b_pending = false;
            }

            // W handshake: accept writes when wvalid && wready
            if (top->io_axi_wvalid && top->io_axi_wready && axi_write_active) {
                axi_awbeat_ix++;
                // if last beat, schedule write response
                if (top->io_axi_wlast) {
                    axi_write_active = false;
                    b_pending = true;
                }
            }

            // B handshake
            if (b_pending && top->io_axi_bready && top->io_axi_bvalid) {
                b_pending = false;
                top->io_axi_bvalid = 0;
            }

            if ((i & 31) == 0) {
                std::cout << "cycle=" << i << " busy=" << (int)top->io_busy << " level=" << std::hex << (int)top->io_level << std::dec << std::endl;
            }

            // detect busy -> idle transition and sample status registers
            bool cur_busy = (int)top->io_busy;
            if (prev_busy && !cur_busy) {
                std::cout << "Transfer finished at cycle=" << i << std::endl;
                uint32_t status = apb_read(0x10); // REG_STATUS
                std::cout << "  REG_STATUS=0x" << std::hex << status << std::dec << std::endl;
                uint32_t level = (uint32_t)top->io_level;
                std::cout << "  FIFO level=" << level << std::endl;
            }
            prev_busy = cur_busy;
        }

    std::cout << "Simulation finished" << std::endl;
#if VM_TRACE
    if (tfp) {
        tfp->close();
        delete tfp;
    }
#endif
    delete top;
    return 0;
}
