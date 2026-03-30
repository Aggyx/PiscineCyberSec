#!/usr/bin/env python3
"""
Mini script para estimar el tamaño máximo que acepta scanf("%s", ...)
antes de provocar fallo (segfault/abort/stack smashing).

Uso:
    python3 find_scanf_limit.py
    python3 find_scanf_limit.py --max-len 2000 --char A
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path


def run_once(binary: Path, payload: str, timeout: float) -> tuple[int, str, str]:
    """Ejecuta el binario una vez enviando payload por stdin.

    Retorna: (returncode, stdout, stderr)
    """
    proc = subprocess.run(
        [str(binary)],
        input=payload + "\n",
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def crashed(returncode: int, stderr: str) -> bool:
    """Heurística de crash: señal, código 139, o mensajes típicos de stack smashing."""
    if returncode < 0:
        return True
    if returncode == 139:  #  segfault code
        return True

    low = stderr.lower()
    return (
        "stack smashing detected" in low
        or "segmentation fault" in low
        or "aborted" in low
    )


def signal_name(returncode: int) -> str:
    if returncode >= 0:
        return ""
    sig = -returncode
    try:
        return signal.Signals(sig).name
    except Exception:
        return f"SIG{sig}"

def main() -> int:
    parser = argparse.ArgumentParser(description="Encuentra longitud que rompe scanf(%s)")
    parser.add_argument("--binary", default="./level1", help="Ruta del binario")
    parser.add_argument("--start", type=int, default=1, help="Longitud inicial")
    parser.add_argument("--max-len", type=int, default=2000, help="Longitud máxima a probar")
    parser.add_argument("--char", default="A", help="Carácter de relleno (1 char)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout por ejecución")
    args = parser.parse_args()

    if len(args.char) != 1:
        print("[!] --char debe ser un único carácter", file=sys.stderr)
        return 2

    binary = Path(args.binary).expanduser().resolve()
    if not binary.exists() or not os.access(binary, os.X_OK):
        print(f"[!] Binario no ejecutable o no encontrado: {binary}", file=sys.stderr)
        return 2

    print(f"[*] Probando {binary} desde longitud {args.start} hasta {args.max_len}...")

    last_ok = None
    first_crash = None

    for n in range(args.start, args.max_len + 1):
        payload = args.char * n
        try:
            rc, out, err = run_once(binary, payload, args.timeout)
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout en longitud {n}")
            first_crash = n
            break

        if crashed(rc, err):
            first_crash = n
            sig = signal_name(rc)
            extra = f" ({sig})" if sig else ""
            print(f"[X] Crash detectado en n={n}, returncode={rc}{extra}")
            if err.strip():
                print(f"    stderr: {err.strip()[:200]}")
            break

        last_ok = n

    if first_crash is None:
        print("[-] No hubo crash en el rango probado.")
        print(f"    Último OK: {last_ok}")
        print("    Sube --max-len para seguir buscando.")
        return 1

    print("\n===== Resultado =====")
    print(f"Último tamaño estable : {last_ok}")
    print(f"Primer tamaño con fallo: {first_crash}")
    if last_ok is not None:
        print(f"Diferencia             : {first_crash - last_ok}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
