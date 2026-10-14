import csv, statistics as st, math
def comp(n,c,mode,k=2):
    # mode: 'pair' (rc1), 'block' (group, prefixed), 'v10' (group, keyed)
    def blk(L): return max(1,math.ceil(L/64))
    def tree(elems,size,g):
        pairs=elems//2; leaves=pairs>>g
        if mode=='pair': ll,nl = 22+2*size, 86
        elif mode=='block': ll,nl = 21+(2<<g)*size, 86
        else: ll,nl = (2<<g)*size, 64
        return leaves+(leaves-1), leaves*blk(ll)+(leaves-1)*blk(nl)
    l0=1<<(n+k); g=lambda d:0 if mode=='pair' else (d-1)
    calls,cp=tree(l0,16,g(min(c,n))); b=c
    while b<n:
        d=min(c,n-b); a,x=tree(l0>>b,32,g(d)); calls+=a; cp+=x; b+=c
    return calls,cp
import sys
rows=list(csv.DictReader(open(sys.argv[1] if len(sys.argv)>1 else "micro.csv")))
print("| n | c | threads | rc1 pair leaves ms | group leaves ms | v0.10 keyed group ms | Δ v0.10 vs rc1 | compressions rc1 → group → v0.10 |")
print("|---|---|---|---|---|---|---|---|")
for th in sorted({r['threads'] for r in rows}, key=int):
  for n in ['16','18','20']:
    for c in ['2','3','4']:
      out={}
      modes=[m for m in ['pair','block','v10'] if any(r['variant']==m for r in rows)]
      for v in modes:
        x=sorted(float(r['commit_ms']) for r in rows if r['variant']==v and r['n']==n and r['c']==c and r['threads']==th)
        if len(x)<2: continue
        q=st.quantiles(x,n=4); out[v]=(st.median(x),q[0],q[2])
      if 'pair' not in out: continue
      f=lambda t:f"{t[0]:.1f} [{t[1]:.1f}–{t[2]:.1f}]" if t else "—"
      last='v10' if 'v10' in out else 'block'
      d=100*(out[last][0]-out['pair'][0])/out['pair'][0]
      cs=" → ".join(f"{comp(int(n),int(c),m)[1]:,}" for m in ['pair','block','v10'])
      print(f"| {n} | {c} | {th} | {f(out.get('pair'))} | {f(out.get('block'))} | {f(out.get('v10'))} | **{d:+.1f}%** | {cs} |")
