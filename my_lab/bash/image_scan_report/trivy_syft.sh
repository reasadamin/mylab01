#!/bin/bash

#Variables
IMAGE_NAME="$1"
SBOM_FILE="sbom.json"
TRIVY_REPORT="trivy-report.json"

# Input Checking
check_input() {
  if [ -z "$IMAGE_NAME" ]; then
    echo "Usage: $0 <image-name>"
    echo "Example: $0 ubuntu:22.04"
    exit 1
  fi
}

# Tools checking
check_tools() {
  if ! command -v syft >/dev/null 2>&1; then
    echo "Error: syft is not installed"
    exit 1
  fi

  if ! command -v trivy >/dev/null 2>&1; then
    echo "Error: trivy is not installed"
    exit 1
  fi
}

# Generating syft report
generate_syft_report() {
  echo "Generating SBOM report with Syft..."
  syft "$IMAGE_NAME" -o json="$SBOM_FILE"

  if [ $? -ne 0 ]; then
    echo "Error: failed to generate SBOM report"
    exit 1
  fi

  echo "SBOM report saved to $SBOM_FILE"
  echo
}

# Generating trivy report
generate_trivy_report() {
  echo "Generating vulnerability report with Trivy..."
  trivy image --format json --output "$TRIVY_REPORT" "$IMAGE_NAME"

  if [ $? -ne 0 ]; then
    echo "Error: failed to generate Trivy report"
    exit 1
  fi

  echo "Trivy report saved to $TRIVY_REPORT"
  echo
}

# Calling all the functions
main() {
  check_input
  check_tools
  generate_syft_report
  generate_trivy_report
  echo "Done. Both reports have been generated successfully."
}

main