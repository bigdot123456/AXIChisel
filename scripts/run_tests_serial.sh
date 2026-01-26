#!/usr/bin/env bash
set -euo pipefail

echo "Running Mill test suites serially..."

mill AXIChisel.test
mill dma.test
mill dmaAXI.test
mill fudian.test

echo "All test suites completed."
