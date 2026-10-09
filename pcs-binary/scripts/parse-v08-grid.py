#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
import csv
import re
import sys
from pathlib import Path

out = Path(sys.argv[1])

def parse_file(path):
    d = {}
    for line in path.read_text().splitlines():
        for k, v in re.findall(r'([A-Za-z0-9_]+)=([^\s]+)', line):
            d[k] = v
    return d

def rss(path):
    if not path.exists():
        return ""
    m = re.search(r'(\d+)\s+maximum resident set size', path.read_text())
    return m.group(1) if m else ""

rows = []
envd = parse_file(out / "environment.txt")

pat = re.compile(r'n(\d+)-t(\d+)-m(\d+)-thr(\d+)\.txt$')

for f in sorted(out.glob("n*-t*-m*-thr*.txt")):
    m = pat.match(f.name)
    if not m:
        continue

    n, t, cm, th = m.groups()
    d = parse_file(f)
    sd = parse_file(out / f"setup-n{n}.txt")

    row = {
        "release_source_commit": envd.get("release_source_commit", ""),
        "release_source_dirty": envd.get("release_source_dirty", ""),
        "public_repo_commit": envd.get("public_repo_commit", ""),
        "public_repo_dirty": envd.get("public_repo_dirty", ""),
        "n": n,
        "k": d.get("k", ""),
        "i0": d.get("i0", ""),
        "m": cm,
        "g": d.get("g", ""),
        "s": d.get("s", ""),
        "t": t,
        "threads": th,
        "runs": d.get("runs", ""),
        "delta_code": d.get("delta_code", ""),
        "delta": d.get("delta", ""),
        "gamma": d.get("gamma", ""),
        "M": d.get("M", ""),
        "N1": d.get("N1", ""),
        "eps_log2": d.get("eps_log2", ""),
        "fold_term_bits": d.get("fold_term_bits", ""),
        "query_term_bits": d.get("query_term_bits", ""),
        "setup_gate_derivation_ms": sd.get("gate_derivation_ms", ""),
        "setup_c3_check_residual_ms": sd.get("c3_check_residual_ms", ""),
        "setup_checked_total_ms": sd.get("setup_checked_total_ms", ""),
        "encode_ms": d.get("encode_ms", ""),
        "commit0_ms": d.get("commit0_ms", ""),
        "fold_ms": d.get("fold_ms", ""),
        "commit_folds_ms": d.get("commit_folds_ms", ""),
        "grind_ms": d.get("grind_ms", ""),
        "openings_ms": d.get("openings_ms", ""),
        "prover_ms": d.get("prover_ms", ""),
        "prover_per_poly_ms": d.get("prover_per_poly_ms", ""),
        "verify_ms": d.get("verify_ms", ""),
        "verify_per_poly_ms": d.get("verify_per_poly_ms", ""),
        "verify_gate_derivation_ms": d.get("verify_gate_derivation_ms", ""),
        "proof_bytes": d.get("proof_bytes", ""),
        "proof_kib": d.get("proof_kib", ""),
        "proof_per_poly_kib": d.get("proof_per_poly_kib", ""),
        "field_bytes": d.get("field_bytes", ""),
        "hash_bytes": d.get("hash_bytes", ""),
        "peak_rss_bytes": rss(f.with_suffix(".time.txt")),
        "verified_runs": d.get("verified_runs", ""),
    }

    try:
        row["fold_plus_commit_ms"] = (
            f"{float(row['fold_ms']) + float(row['commit_folds_ms']):.3f}"
        )
    except Exception:
        row["fold_plus_commit_ms"] = ""

    rows.append(row)

rows.sort(key=lambda r: (
    int(r["threads"]),
    int(r["n"]),
    int(r["t"]),
    int(r["m"]),
))

if not rows:
    raise SystemExit("no benchmark rows found")

with (out / "v08-final-grid.csv").open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

def num(x, digits=1):
    try:
        return f"{float(x):.{digits}f}"
    except Exception:
        return "--"

runs = rows[0]["runs"] or "?"
run_word = "run" if runs == "1" else "runs"

tex = [
    r"\begin{table}[t]",
    r"\centering",
    rf"\caption{{SPARK v0.8 implementation results. Times are median of {runs} {run_word}.}}",
    r"\label{tab:impl-v08}",
    r"\begin{tabular}{lrrrr}",
    r"\toprule",
    r"Configuration & Prover (ms) & Verifier (ms) & Proof (KiB) & Per polynomial (ms) \\",
    r"\midrule",
]

for th in ("1", "8"):
    for r in rows:
        if r["threads"] != th:
            continue
        label = f"$n={r['n']},t={r['t']},m={r['m']},\\mathrm{{th}}={th}$"
        tex.append(
            f"{label} & {num(r['prover_ms'])} & {num(r['verify_ms'])} & "
            f"{num(r['proof_kib'])} & {num(r['prover_per_poly_ms'])} \\\\"
        )
    if th == "1":
        tex.append(r"\midrule")

tex += [
    r"\bottomrule",
    r"\end{tabular}",
    r"\end{table}",
]

(out / "v08-final-grid.tex").write_text("\n".join(tex) + "\n")

detail = [
    r"\begin{table*}[t]",
    r"\centering",
    rf"\caption{{SPARK v0.8 timing breakdown, median of {runs} {run_word}.}}",
    r"\begin{tabular}{lrrrrrrrr}",
    r"\toprule",
    r"Configuration & Encode & Commit & Fold & Fold-commit & Grind & Openings & Verify gates & Total \\",
    r"\midrule",
]

for r in rows:
    label = f"$n={r['n']},t={r['t']},m={r['m']},\\mathrm{{th}}={r['threads']}$"
    detail.append(
        f"{label} & {num(r['encode_ms'])} & {num(r['commit0_ms'])} & "
        f"{num(r['fold_ms'])} & {num(r['commit_folds_ms'])} & "
        f"{num(r['grind_ms'])} & {num(r['openings_ms'])} & "
        f"{num(r['verify_gate_derivation_ms'])} & {num(r['prover_ms'])} \\\\"
    )

detail += [
    r"\bottomrule",
    r"\end{tabular}",
    r"\end{table*}",
]

(out / "v08-final-grid-breakdown.tex").write_text("\n".join(detail) + "\n")

print(out / "v08-final-grid.csv")
print(out / "v08-final-grid.tex")
print(out / "v08-final-grid-breakdown.tex")
