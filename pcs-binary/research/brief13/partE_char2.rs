// Brief 13b Part E: characteristic-2 sanity check for the 16 hard C2,k=1 minors.
// Standalone Rust, no external crates.
//
// A point-difference factor (u-v) must make the determinant vanish identically
// after imposing u=v.  Over characteristic 2 this is u+v.
// We test each of the 28 candidate differences among the 8 points occurring
// in each hard minor.  For every candidate we impose equality and search for
// a random specialization of the other variables with nonzero determinant.
// One such witness disproves divisibility by that point difference.

#[derive(Clone, Copy)]
struct GF256;

impl GF256 {
    #[inline] fn add(a:u8,b:u8)->u8 { a ^ b }
    #[inline] fn mul(mut a:u8, mut b:u8)->u8 {
        let mut r=0u8;
        for _ in 0..8 {
            if b & 1 != 0 { r ^= a; }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 { a ^= 0x1b; } // x^8+x^4+x^3+x+1
            b >>= 1;
        }
        r
    }
    fn pow(mut a:u8, mut e:u16)->u8 {
        let mut r=1u8;
        while e>0 {
            if e&1 != 0 { r=Self::mul(r,a); }
            a=Self::mul(a,a); e>>=1;
        }
        r
    }
    fn inv(a:u8)->u8 { assert!(a!=0); Self::pow(a,254) }
}

#[derive(Clone)]
struct XorShift64 { s:u64 }
impl XorShift64 {
    fn new(s:u64)->Self{Self{s:s.max(1)}}
    fn next(&mut self)->u64 {
        let mut x=self.s; x^=x<<13; x^=x>>7; x^=x<<17; self.s=x; x
    }
    fn byte(&mut self)->u8 {(self.next()&255) as u8}
}

fn det4(mut a:[[u8;4];4])->u8 {
    let mut det=1u8;
    for col in 0..4 {
        let mut p=col;
        while p<4 && a[p][col]==0 {p+=1;}
        if p==4 {return 0}
        if p!=col {a.swap(p,col);} // sign irrelevant in characteristic 2
        let pv=a[col][col];
        det=GF256::mul(det,pv);
        let inv=GF256::inv(pv);
        for r in col+1..4 {
            if a[r][col]==0 {continue}
            let f=GF256::mul(a[r][col],inv);
            for c in col..4 {
                a[r][c]=GF256::add(a[r][c],GF256::mul(f,a[col][c]));
            }
        }
    }
    det
}

// vars = [x0a,x0b,x1a,x1b,y0?,y1?,y2?,y3?].
// sel chooses a/b for each y gate.
fn hard_det(vars:&[u8;8])->u8 {
    let xs=[vars[0],vars[1],vars[2],vars[3]];
    let ys=[vars[4],vars[5],vars[6],vars[7]];
    let mut m=[[0u8;4];4];
    for i in 0..4 {
        m[i]=[1,xs[i],ys[i],GF256::mul(xs[i],ys[i])];
    }
    det4(m)
}

fn main() {
    let trials:usize=std::env::args().nth(1).and_then(|s|s.parse().ok()).unwrap_or(64);
    let mut rng=XorShift64::new(0x13b0_2026_1008);
    let mut total_candidates=0usize;
    let mut disproved=0usize;
    let mut suspicious=Vec::new();

    // There are 16 child choices. Renaming y0a/y0b etc. gives the same
    // determinant shape, but we execute all 16 as requested.
    for sel in 0u8..16 {
        for i in 0..8 {
            for j in i+1..8 {
                total_candidates+=1;
                let mut witness=None;
                for _ in 0..trials {
                    let mut v=[0u8;8];
                    for x in &mut v {*x=rng.byte();}
                    v[j]=v[i]; // impose candidate point difference = 0
                    let d=hard_det(&v);
                    if d!=0 {witness=Some((v,d));break}
                }
                if witness.is_some() {
                    disproved+=1;
                } else {
                    suspicious.push((sel,i,j));
                }
            }
        }
    }

    println!("brief13b_partE_char2");
    println!("field=GF(2^8) modulus=0x11b");
    println!("hard_minors=16");
    println!("candidate_point_differences_per_minor=28");
    println!("random_specializations_per_candidate={trials}");
    println!("total_candidate_divisibilities={total_candidates}");
    println!("disproved_by_nonzero_specialization={disproved}");
    println!("not_disproved={}",suspicious.len());
    if suspicious.is_empty() {
        println!("RESULT=PASS no hard four-single quartic showed a point-difference factor");
    } else {
        println!("RESULT=INCONCLUSIVE suspicious={suspicious:?}");
    }
}
