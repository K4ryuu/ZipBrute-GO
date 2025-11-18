#!/bin/bash

case "$1" in
  build)
    echo "[*] building with optimizations..."
    GOAMD64=v3 go build -ldflags="-s -w" -gcflags="-l=4" -o zipcracker main.go
    if [ $? -eq 0 ]; then
      echo "[+] build ok"
      ls -lh zipcracker | awk '{print "[*] size: " $5}'
    else
      echo "[-] build failed"
      exit 1
    fi
    ;;

  run)
    if [ ! -f "./zipcracker" ]; then
      echo "[-] binary not found, building..."
      $0 build || exit 1
    fi

    ZIP="${2:-fontos_projektem.zip}"
    CHARSET="${3:-lower+digits}"
    MIN="${4:-1}"
    MAX="${5:-8}"

    ./zipcracker -f "$ZIP" -c "$CHARSET" -min "$MIN" -max "$MAX" --auto
    ;;

  *)
    echo "usage: $0 {build|run} [zip] [charset] [min] [max]"
    echo ""
    echo "examples:"
    echo "  $0 build"
    echo "  $0 run"
    echo "  $0 run file.zip lower+digits 1 8"
    exit 1
    ;;
esac
