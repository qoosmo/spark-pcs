#!/usr/bin/env python3
"""
Brief 13 Part E exploratory factorization.
Requires: pip install sympy

Exact:
  * C2, k=0
  * all 70 C2, k=1 minors

For C3,k=0 the determinant is reported from the recursive square-tree
factorization rather than expanded naively.

This is exploration only, not the final Rust certificate.
"""
import itertools, collections, json
from pathlib import Path
import sympy as sp

def pv(prefix, n):
    return [(sp.symbols(f"{prefix}{i}a"), sp.symbols(f"{prefix}{i}b")) for i in range(n)]

def c2_rows(k):
    l0=pv("x",1<<k); l1=pv("y",1<<(k+1))
    rows=[]; labels=[]
    for beta in range(1<<k):
        for b1 in range(2):
            p1=(beta<<1)|b1
            x=l0[beta][b1]
            for b2 in range(2):
                y=l1[p1][b2]
                rows.append([1,x,y,x*y])
                labels.append((beta,b1,b2))
    return rows,labels,l0,l1

def factor_profile(expr):
    coeff, facs=sp.factor_list(expr)
    return [(sp.total_degree(f),len(f.free_symbols),e,str(f)) for f,e in facs]

def main():
    # C2,k=0
    rows,labels,l0,l1=c2_rows(0)
    d0=sp.factor(sp.Matrix(rows).det(method="domain-ge"))
    print("=== C2 k=0 ===")
    print("minor_count=1")
    print("det =", d0)
    print()

    # C2,k=1, all 70 minors
    rows,labels,l0,l1=c2_rows(1)
    profile_counts=collections.Counter()
    class_examples={}
    details=[]
    for comb in itertools.combinations(range(8),4):
        mat=sp.Matrix([rows[i] for i in comb])
        det=sp.factor(mat.det(method="domain-ge"))
        coeff,facs=sp.factor_list(det)
        block_counts=collections.Counter(((labels[i][0]<<1)|labels[i][1]) for i in comb)
        block_pattern=tuple(sorted(block_counts.values(),reverse=True))
        coarse=tuple(sorted((sp.total_degree(f),len(f.free_symbols),e) for f,e in facs))
        key=(block_pattern,coarse)
        profile_counts[key]+=1
        class_examples.setdefault(key,(comb,det))
        details.append({
            "rows":comb,
            "labels":[labels[i] for i in comb],
            "block_pattern":block_pattern,
            "factor_profile":coarse,
            "factorization":str(det),
        })

    print("=== C2 k=1 ===")
    print("minor_count=",len(details))
    for key,count in sorted(profile_counts.items(), key=lambda kv: str(kv[0])):
        print("count=",count,"block_pattern=",key[0],"factor_profile=",key[1])
        comb,det=class_examples[key]
        print(" example rows=",comb)
        print(" example det =",det)
    print()
    Path("brief13-c2-k1-factors.json").write_text(json.dumps(details,indent=2))
    print("wrote brief13-c2-k1-factors.json")

    # C3,k=0 square tree.  The recursive encoder determinant is the product
    # of local gate determinants with multiplicities 4,2,1.
    x=pv("x",1)
    y=pv("y",2)
    z=pv("z",4)
    c3det=(x[0][1]-x[0][0])**4
    for a,b in y: c3det *= (b-a)**2
    for a,b in z: c3det *= (b-a)
    print()
    print("=== C3 k=0 (recursive exact factorization) ===")
    print("minor_count=1")
    print("det =",sp.factor(c3det))
    print("total_degree=",sp.total_degree(c3det))
    print("support_size=",len(c3det.free_symbols))

if __name__=="__main__":
    main()
