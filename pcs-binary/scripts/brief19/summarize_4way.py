import csv, sys, statistics as st
rows = list(csv.DictReader(open(sys.argv[1])))
order = ["random-rc1", "tplus1-rc1", "random-v10", "tplus1-v10"]
label = {"random-rc1": "v0.9.1-equiv (random gates, pair leaves)", "tplus1-rc1": "v0.10-rc1 ((t,t+1), pair leaves)",
         "random-v10": "random gates, v0.10 leaves", "tplus1-v10": "v0.10 ((t,t+1), keyed group leaves)"}
def med(xs):
    xs = sorted(xs); q = st.quantiles(xs, n=4); return st.median(xs), q[0], q[2]
for th in sorted({r["threads"] for r in rows}, key=int):
    for c in sorted({r["c"] for r in rows}, key=int):
        sel = [r for r in rows if r["threads"] == th and r["c"] == c]
        if not sel: continue
        print(f"\n### n=20, m={c}, threads={th}\n")
        print("| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |")
        print("|---|---|---|---|---|---|---|---|---|")
        base = None
        for v in order:
            R = [r for r in sel if r["variant"] == v]
            if not R: continue
            enc = med([float(r["encode_ms"]) for r in R])[0]
            com = med([float(r["commit0_ms"]) + float(r["commit_folds_ms"]) for r in R])[0]
            fol = med([float(r["fold_ms"]) for r in R])[0]
            tot = med([float(r["prover_total_ms"]) for r in R])
            ver = med([float(r["verify_ms"]) for r in R])[0]
            if base is None: base = tot[0]
            print(f"| {label[v]} | {len(R)} | {enc:.0f} | {com:.0f} | {fol:.0f} | {tot[0]:.0f} [{tot[1]:.0f}–{tot[2]:.0f}] | {base/tot[0]:.2f}× | {ver:.1f} | {R[0]['proof_bytes']} |")
