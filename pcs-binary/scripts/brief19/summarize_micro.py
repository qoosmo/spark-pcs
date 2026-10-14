import csv, statistics as st, math
def comp(n,c,block,k=2):
    def blk(L): return max(1,math.ceil(L/64))
    def tree(elems,size,g):
        pairs=elems//2; leaves=pairs>>g
        ll = 22+2*size if g==0 else 21+(2<<g)*size
        return leaves+(leaves-1), leaves*blk(ll)+(leaves-1)*blk(86)
    l0=1<<(n+k); g=lambda d:(d-1) if block else 0
    calls,cp=tree(l0,16,g(min(c,n))); b=c
    while b<n:
        d=min(c,n-b); a,x=tree(l0>>b,32,g(d)); calls+=a; cp+=x; b+=c
    return calls,cp
import sys
rows=list(csv.DictReader(open(sys.argv[1] if len(sys.argv)>1 else "micro.csv")))
print("| n | c | threads | pair commit ms (median [IQR]) | block commit ms | Δ time | compressions pair → block | Δ comp | ns/compression pair / block |")
print("|---|---|---|---|---|---|---|---|---|")
for th in sorted({r['threads'] for r in rows}, key=int):
  for n in ['16','18','20']:
    for c in ['2','3','4']:
      out={}
      for v in ['pair','block']:
        x=sorted(float(r['commit_ms']) for r in rows if r['variant']==v and r['n']==n and r['c']==c and r['threads']==th)
        q=st.quantiles(x,n=4); out[v]=(st.median(x),q[0],q[2])
      cp=comp(int(n),int(c),False)[1]; cb=comp(int(n),int(c),True)[1]
      d=100*(out['block'][0]-out['pair'][0])/out['pair'][0]
      f=lambda t:f"{t[0]:.1f} [{t[1]:.1f}–{t[2]:.1f}]"
      nsp=out['pair'][0]*1e6/cp; nsb=out['block'][0]*1e6/cb
      print(f"| {n} | {c} | {th} | {f(out['pair'])} | {f(out['block'])} | **{d:+.1f}%** | {cp:,} → {cb:,} | {100*(cb-cp)/cp:+.1f}% | {nsp:.0f} / {nsb:.0f} |")
