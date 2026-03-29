#!/bin/bash

SBOM_FILE="$1"

check_file() {
  if [ -z "$SBOM_FILE" ]; then
    echo "Usage: $0 <sbom.json>"
    exit 1
  fi

  if [ ! -f "$SBOM_FILE" ]; then
    echo "Error: File not found - $SBOM_FILE"
    exit 1
  fi
}

list_components() {
  echo "=== Component List ==="
  jq -r '.artifacts[] | "\(.name):\(.version)"' "$SBOM_FILE"
  echo
}

count_total_components() {
  echo "=== Total Component Count ==="
  jq '.artifacts | length' "$SBOM_FILE"
  echo
}

show_component_types() {
  echo "=== Component Types ==="
  jq -r '.artifacts[] | "\(.name):\(.type)"' "$SBOM_FILE"
  echo
}

extract_licenses() {
  echo "=== Licenses ==="
  jq -r '.artifacts[] | "\(.name):\(.licenses[]?.value // "No license found")"' "$SBOM_FILE"
  echo
}

main() {
  check_file
  list_components
  count_total_components
  show_component_types
  extract_licenses
}

main