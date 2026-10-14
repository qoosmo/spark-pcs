import csv, sys, statistics as st
rows=list(csv.DictReader(open(sys.argv[1])))
keys=sorted({(r['n'],r['c'],r['threads']) for r in rows}, key=lambda k:(int(k[2]),int(k[0]),int(k[1])))
cols=['encode_ms','commit0_ms','fold_ms','commit_folds_ms','prover_core_ms','prover_total_ms','verify_ms']
def q(v):
    v=sorted(v); m=st.median(v)
    qs=st.quantiles(v,n=4) if len(v)>=4 else [v[0],m,v[-1]]
    return m,qs[0],qs[2]
print("| n | c | thr | variant | commit (ms) | prover core (ms) | prover total (ms) | verify (ms) | proof bytes | hash calls | compressions |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for k in keys:
    res={}
    for var in ['pair','block']:
        R=[r for r in rows if (r['n'],r['c'],r['threads'])==k and r['variant']==var]
        if not R: continue
        commit=[float(r['commit0_ms'])+float(r['commit_folds_ms']) for r in R]
        core=[float(r['prover_core_ms']) for r in R]
        tot=[float(r['prover_total_ms']) for r in R]
        ver=[float(r['verify_ms']) for r in R]
        res[var]=dict(commit=q(commit),core=q(core),tot=q(tot),ver=q(ver),bytes=R[0]['proof_bytes'],calls=R[0]['hash_calls'],comp=R[0]['compressions'],N=len(R))
        f=lambda t:f"{t[0]:.1f} [{t[1]:.1f}–{t[2]:.1f}]"
        print(f"| {k[0]} | {k[1]} | {k[2]} | {var} (N={len(R)}) | {f(res[var]['commit'])} | {f(res[var]['core'])} | {f(res[var]['tot'])} | {f(res[var]['ver'])} | {res[var]['bytes']} | {res[var]['calls']} | {res[var]['comp']} |")
    if 'pair' in res and 'block' in res:
        d=lambda a:100*(res['block'][a][0]-res['pair'][a][0])/res['pair'][a][0]
        print(f"| | | | **Δ block vs pair** | {d('commit'):+.1f}% | {d('core'):+.1f}% | {d('tot'):+.1f}% | {d('ver'):+.1f}% | {100*(int(res['block']['bytes'])-int(res['pair']['bytes']))/int(res['pair']['bytes']):+.2f}% | {100*(int(res['block']['calls'])-int(res['pair']['calls']))/int(res['pair']['calls']):+.1f}% | {100*(int(res['block']['comp'])-int(res['pair']['comp']))/int(res['pair']['comp']):+.1f}% |")
