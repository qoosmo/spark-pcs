// Brief 13b Part D exact experiment.
// Rust only, no external crates.
//
// Goals:
// - exact list decoding for every tested challenge r;
// - random, planted, and adversarial (hill-climbed) A,B;
// - several random SPARK gate families per parameter set;
// - random linear-code controls with the same [L,D];
// - every integer radius e with d/2 < e < Johnson, plus e=floor((d-1)/2);
// - exact correlated-line test under the agent's agreement-set definition.
//
// Usage:
//   cargo run --release --bin brief13_partd -- [families] [random_trials] [planted_trials] [hill_iters]
//
// Defaults are 5, 6, 3, 40.

use std::cmp::Ordering;

#[derive(Clone,Copy,Debug)]
struct GF { m:u32, poly:u16, q:u8, name:&'static str }
impl GF {
    #[inline] fn add(self,a:u8,b:u8)->u8{a^b}
    #[inline] fn mul(self,mut a:u8,mut b:u8)->u8{
        let mut r=0u8;
        let top=1u16<<self.m;
        let mask=(self.q as u16)-1;
        while b!=0 {
            if b&1!=0 {r^=a;}
            b>>=1;
            let aa=(a as u16)<<1;
            let red=if aa&top!=0 {aa^self.poly}else{aa};
            a=(red&mask) as u8;
        }
        r
    }
    fn pow(self,mut a:u8,mut e:u32)->u8{
        let mut r=1u8;
        while e>0 {if e&1!=0{r=self.mul(r,a);} a=self.mul(a,a); e>>=1;}
        r
    }
    fn inv(self,a:u8)->u8{assert!(a!=0);self.pow(a,self.q as u32-2)}
}

#[derive(Clone)]
struct Rng64{ s:u64 }
impl Rng64 {
    fn new(s:u64)->Self{Self{s:s.max(1)}}
    fn next(&mut self)->u64{let mut x=self.s;x^=x<<13;x^=x>>7;x^=x<<17;self.s=x;x}
    fn elt(&mut self,f:GF)->u8{(self.next()%(f.q as u64)) as u8}
    fn usize(&mut self,n:usize)->usize{(self.next()%(n as u64)) as usize}
}

#[derive(Clone)]
struct Code {
    field:GF,
    n:usize,
    k:usize,
    l:usize,
    d:usize,
    gen:Vec<u8>, // row-major L x D
    label:String,
    seed:u64,
    checked:bool,
}

#[derive(Clone)]
struct Book {
    code:Code,
    msgs:Vec<u8>, // N x D
    cws:Vec<u8>,  // N x L
    nwords:usize,
    mindist:usize,
}

fn rank(mut a:Vec<Vec<u8>>, f:GF)->usize{
    if a.is_empty(){return 0}
    let nr=a.len(); let nc=a[0].len(); let mut r=0usize;
    for c in 0..nc {
        let mut p=r;
        while p<nr && a[p][c]==0 {p+=1;}
        if p==nr {continue}
        a.swap(r,p);
        let inv=f.inv(a[r][c]);
        for j in c..nc {a[r][j]=f.mul(a[r][j],inv);}
        for i in 0..nr {
            if i==r || a[i][c]==0 {continue}
            let q=a[i][c];
            for j in c..nc {a[i][j]=f.add(a[i][j],f.mul(q,a[r][j]));}
        }
        r+=1; if r==nr {break}
    }
    r
}

fn next_comb(c:&mut [usize], n:usize)->bool{
    let k=c.len();
    for i in (0..k).rev() {
        if c[i] < n-k+i {
            c[i]+=1;
            for j in i+1..k {c[j]=c[j-1]+1;}
            return true
        }
    }
    false
}

fn is_mds_generator(gen:&[u8],l:usize,d:usize,f:GF)->bool{
    if d==0 || d>l{return false}
    let mut c=(0..d).collect::<Vec<_>>();
    loop {
        let mut a=vec![vec![0u8;d];d];
        for i in 0..d {a[i].copy_from_slice(&gen[c[i]*d..(c[i]+1)*d]);}
        if rank(a,f)!=d{return false}
        if !next_comb(&mut c,l){break}
    }
    true
}

fn spark_generator(n:usize,k:usize,f:GF,seed:u64,checked:bool)->Code{
    let mut rng=Rng64::new(seed);
    let mut gates:Vec<Vec<(u8,u8)>>=Vec::new();
    for level in 0..n {
        let cnt=1usize<<(k+level);
        let mut v=Vec::with_capacity(cnt);
        for _ in 0..cnt {
            let a=rng.elt(f); let mut b=rng.elt(f);
            if b==a {b^=1; if b>=f.q {b=0;}}
            if b==a {b=(a+1)%f.q;}
            v.push((a,b));
        }
        gates.push(v);
    }
    let l=1usize<<(n+k); let d=1usize<<n;
    let mut gen=vec![0u8;l*d];
    for pos in 0..l {
        let beta=pos>>n;
        let mut prefix=beta;
        let mut ys=vec![0u8;n];
        for level in 0..n {
            let bit=(pos>>(n-1-level))&1;
            let pair=gates[level][prefix];
            ys[level]=if bit==0{pair.0}else{pair.1};
            prefix=(prefix<<1)|bit;
        }
        for mask in 0..d {
            let mut v=1u8;
            for j in 0..n {
                if (mask>>(n-1-j))&1!=0 {v=f.mul(v,ys[j]);}
            }
            gen[pos*d+mask]=v;
        }
    }
    Code{field:f,n,k,l,d,gen,label:if checked{"spark_checked".into()}else{"spark".into()},seed,checked}
}

fn random_linear_code(l:usize,d:usize,f:GF,seed:u64)->Code{
    let mut rng=Rng64::new(seed);
    loop {
        let mut gen=vec![0u8;l*d];
        for x in &mut gen {*x=rng.elt(f);}
        let rows=(0..l).map(|i|gen[i*d..(i+1)*d].to_vec()).collect::<Vec<_>>();
        if rank(rows,f)==d {
            return Code{field:f,n:d.trailing_zeros() as usize,k:0,l,d,gen,label:"random".into(),seed,checked:false}
        }
    }
}

fn book(code:Code)->Book{
    let f=code.field; let total=(f.q as usize).pow(code.d as u32);
    let mut msgs=vec![0u8;total*code.d];
    let mut cws=vec![0u8;total*code.l];
    let mut mindist=code.l+1;
    for idx in 0..total {
        let mut z=idx;
        for j in 0..code.d {msgs[idx*code.d+j]=(z%(f.q as usize)) as u8;z/=f.q as usize;}
        for p in 0..code.l {
            let mut s=0u8;
            for j in 0..code.d {
                s=f.add(s,f.mul(msgs[idx*code.d+j],code.gen[p*code.d+j]));
            }
            cws[idx*code.l+p]=s;
        }
        if idx!=0 {
            let w=cws[idx*code.l..(idx+1)*code.l].iter().filter(|&&x|x!=0).count();
            if w<mindist {mindist=w;}
        }
    }
    Book{code,msgs,cws,nwords:total,mindist}
}

#[derive(Clone,Copy,Debug,Default)]
struct Score { nclose:usize,npairs:usize,lmax:usize,u:usize,covered:bool }
impl Score {
    fn cmp_obj(&self,o:&Self)->Ordering{
        (self.u,self.nclose,self.npairs,self.lmax).cmp(&(o.u,o.nclose,o.npairs,o.lmax))
    }
}

fn decode_lists(a:&[u8],b:&[u8],bk:&Book,e:usize)->Vec<Vec<usize>>{
    let f=bk.code.field; let mut out=vec![Vec::<usize>::new();f.q as usize];
    for r in 0..f.q {
        for ci in 0..bk.nwords {
            let cw=&bk.cws[ci*bk.code.l..(ci+1)*bk.code.l];
            let mut dd=0usize;
            for p in 0..bk.code.l {
                let y=f.add(a[p],f.mul(r,b[p]));
                if y!=cw[p] {dd+=1;if dd>e{break}}
            }
            if dd<=e {out[r as usize].push(ci);}
        }
    }
    out
}

fn line_pair_from_two(bk:&Book,c1:usize,r1:u8,c2:usize,r2:u8)->(Vec<u8>,Vec<u8>){
    let f=bk.code.field; let den=f.inv(f.add(r1,r2));
    let w1=&bk.cws[c1*bk.code.l..(c1+1)*bk.code.l];
    let w2=&bk.cws[c2*bk.code.l..(c2+1)*bk.code.l];
    let mut bb=vec![0u8;bk.code.l]; let mut aa=vec![0u8;bk.code.l];
    for p in 0..bk.code.l {
        bb[p]=f.mul(f.add(w1[p],w2[p]),den);
        aa[p]=f.add(w1[p],f.mul(r1,bb[p]));
    }
    (aa,bb)
}

fn has_correlated_line(a:&[u8],b:&[u8],bk:&Book,e:usize,lists:&[Vec<usize>])->bool{
    let active=(0..lists.len()).filter(|&r|!lists[r].is_empty()).collect::<Vec<_>>();
    if active.len()<2 {return false}
    // Any globally correlated line is close for every challenge, hence appears
    // in every pair of active decoded lists.  Use the two smallest lists.
    let mut pairs=Vec::new();
    for i in 0..active.len(){for j in i+1..active.len(){pairs.push((active[i],active[j]));}}
    pairs.sort_by_key(|&(r,s)|lists[r].len()*lists[s].len());
    let (r1,r2)=pairs[0];
    for &c1 in &lists[r1] {
        for &c2 in &lists[r2] {
            let (aa,bb)=line_pair_from_two(bk,c1,r1 as u8,c2,r2 as u8);
            let mut bad=0usize;
            for p in 0..bk.code.l {
                if a[p]!=aa[p] || b[p]!=bb[p] {bad+=1;if bad>e{break}}
            }
            if bad<=e {return true}
        }
    }
    false
}

// Exact per-challenge coverage from Brief 13b.
//
// For fixed r and close codeword c in List(r), choose any codeword b_code and set
//     a_code = c + r * b_code.
// By linearity a_code is a codeword.  We then test exactly whether
//     #{p : (A[p],B[p]) != (a_code[p],b_code[p])} <= e.
//
// Enumerating all b_code is exact for these small experiments.
fn challenge_covered_exact(
    a:&[u8],
    b:&[u8],
    bk:&Book,
    e:usize,
    r:u8,
    close:&[usize],
)->bool{
    let f=bk.code.field;
    let l=bk.code.l;

    for &ci in close {
        let c=&bk.cws[ci*l..(ci+1)*l];

        for bi in 0..bk.nwords {
            let bw=&bk.cws[bi*l..(bi+1)*l];
            let mut bad=0usize;

            for p in 0..l {
                let aw=f.add(c[p],f.mul(r,bw[p]));
                if a[p]!=aw || b[p]!=bw[p] {
                    bad+=1;
                    if bad>e { break; }
                }
            }

            if bad<=e {
                return true;
            }
        }
    }

    false
}

fn score(a:&[u8],b:&[u8],bk:&Book,e:usize)->Score{
    let lists=decode_lists(a,b,bk,e);
    let nclose=lists.iter().filter(|x|!x.is_empty()).count();
    let npairs=lists.iter().map(|x|x.len()).sum();
    let lmax=lists.iter().map(|x|x.len()).max().unwrap_or(0);

    // Brief 13b defines U per challenge r.
    let mut u=0usize;
    for r in 0..lists.len() {
        if lists[r].is_empty() { continue; }
        if !challenge_covered_exact(a,b,bk,e,r as u8,&lists[r]) {
            u+=1;
        }
    }

    let covered = nclose>0 && u==0;
    Score{nclose,npairs,lmax,u,covered}
}

fn random_word(l:usize,f:GF,rng:&mut Rng64)->Vec<u8>{(0..l).map(|_|rng.elt(f)).collect()}

fn planted_pair(bk:&Book,e:usize,rng:&mut Rng64)->(Vec<u8>,Vec<u8>){
    let ia=rng.usize(bk.nwords); let ib=rng.usize(bk.nwords);
    let mut a=bk.cws[ia*bk.code.l..(ia+1)*bk.code.l].to_vec();
    let mut b=bk.cws[ib*bk.code.l..(ib+1)*bk.code.l].to_vec();
    let mut pos=(0..bk.code.l).collect::<Vec<_>>();
    for i in 0..e {
        let j=i+rng.usize(bk.code.l-i); pos.swap(i,j);
        let p=pos[i];
        if rng.next()&1==0 {
            let old=a[p]; let mut x=rng.elt(bk.code.field); if x==old{x^=1;if x>=bk.code.field.q{x=0}}; if x==old{x=(old+1)%bk.code.field.q}; a[p]=x;
        } else {
            let old=b[p]; let mut x=rng.elt(bk.code.field); if x==old{x^=1;if x>=bk.code.field.q{x=0}}; if x==old{x=(old+1)%bk.code.field.q}; b[p]=x;
        }
    }
    (a,b)
}

fn hill_climb(bk:&Book,e:usize,iters:usize,rng:&mut Rng64)->(Vec<u8>,Vec<u8>,Score){
    let mut a=random_word(bk.code.l,bk.code.field,rng);
    let mut b=random_word(bk.code.l,bk.code.field,rng);
    let mut sc=score(&a,&b,bk,e);
    for _ in 0..iters {
        let which=rng.next()&1;
        let p=rng.usize(bk.code.l);
        let old=if which==0{a[p]}else{b[p]};
        let mut nw=rng.elt(bk.code.field);
        if nw==old{nw^=1;if nw>=bk.code.field.q{nw=0}}; if nw==old{nw=(old+1)%bk.code.field.q}
        if which==0{a[p]=nw}else{b[p]=nw}
        let ns=score(&a,&b,bk,e);
        if ns.cmp_obj(&sc)==Ordering::Less {
            if which==0{a[p]=old}else{b[p]=old}
        } else {
            sc=ns;
        }
    }
    (a,b,sc)
}

#[derive(Clone)]
struct Best { score:Score, kind:&'static str, a:Vec<u8>, b:Vec<u8> }
impl Default for Best {
    fn default()->Self{Self{score:Score::default(),kind:"none",a:Vec::new(),b:Vec::new()}}
}
fn consider(best:&mut Best,sc:Score,kind:&'static str,a:&[u8],b:&[u8]){
    if sc.cmp_obj(&best.score)==Ordering::Greater {
        *best=Best{score:sc,kind,a:a.to_vec(),b:b.to_vec()};
    }
}

fn radii(bk:&Book)->Vec<(usize,&'static str)>{
    let d=bk.mindist; let l=bk.code.l;
    let mut out=Vec::new();
    let below=(d.saturating_sub(1))/2;
    out.push((below,"below_half"));
    let delta=d as f64/l as f64;
    let j=(1.0-(1.0-delta).sqrt())*l as f64;
    for e in 0..=l {
        if 2*e>d && (e as f64)<j-1e-12 {out.push((e,"above_half"));}
    }
    out
}

fn run_radius(bk:&Book,e:usize,zone:&'static str,random_trials:usize,planted_trials:usize,hill_iters:usize,seed:u64)->Best{
    let mut rng=Rng64::new(seed);
    let mut best=Best::default();
    for _ in 0..random_trials {
        let a=random_word(bk.code.l,bk.code.field,&mut rng);
        let b=random_word(bk.code.l,bk.code.field,&mut rng);
        let sc=score(&a,&b,bk,e); consider(&mut best,sc,"random",&a,&b);
    }
    for _ in 0..planted_trials {
        let (a,b)=planted_pair(bk,e,&mut rng);
        let sc=score(&a,&b,bk,e); consider(&mut best,sc,"planted",&a,&b);
    }
    for _ in 0..2 {
        let (a,b,sc)=hill_climb(bk,e,hill_iters,&mut rng);
        consider(&mut best,sc,"adversarial",&a,&b);
    }
    let ratio=best.score.u as f64/bk.code.l as f64;
    println!(
        "ROW code={} field={} n={} k={} L={} D={} family_seed={} checked={} d={} Delta={:.6} zone={} e={} delta={:.6} N_close={} N_pairs={} L_max={} U={} U_over_L={:.6} covered={} source={}",
        bk.code.label,bk.code.field.name,bk.code.n,bk.code.k,bk.code.l,bk.code.d,bk.code.seed,bk.code.checked,bk.mindist,
        bk.mindist as f64/bk.code.l as f64,zone,e,e as f64/bk.code.l as f64,
        best.score.nclose,best.score.npairs,best.score.lmax,best.score.u,ratio,best.score.covered,best.kind
    );
    if best.score.u>bk.code.l || best.score.u==bk.code.field.q as usize {
        println!("INSTANCE code={} field={} n={} k={} seed={} e={} U={} A={:?} B={:?}",
            bk.code.label,bk.code.field.name,bk.code.n,bk.code.k,bk.code.seed,e,best.score.u,best.a,best.b);
    }
    if zone=="below_half" && best.score.nclose>=2 {
        let lists=decode_lists(&best.a,&best.b,bk,e);
        if !has_correlated_line(&best.a,&best.b,bk,e,&lists) {
            println!("SANITY_WARNING below_half_multiple_close_without_ONE_global_correlated_line seed={} e={} A={:?} B={:?}",
                bk.code.seed,e,best.a,best.b);
        }
    }
    best
}

fn run_book(bk:Book,random_trials:usize,planted_trials:usize,hill_iters:usize,seed:u64){
    println!("CODE code={} field={} n={} k={} L={} D={} seed={} checked={} d={} Delta={:.6}",
        bk.code.label,bk.code.field.name,bk.code.n,bk.code.k,bk.code.l,bk.code.d,bk.code.seed,bk.code.checked,bk.mindist,bk.mindist as f64/bk.code.l as f64);
    let rs=radii(&bk);
    let above=rs.iter().filter(|(_,z)|*z=="above_half").count();
    println!("RADII above_half_count={} list={:?}",above,rs);
    for (ix,(e,z)) in rs.into_iter().enumerate() {
        run_radius(&bk,e,z,random_trials,planted_trials,hill_iters,seed^(ix as u64).wrapping_mul(0x9e3779b97f4a7c15));
    }
}

fn find_checked(n:usize,k:usize,f:GF,start:u64,max_tries:usize)->Option<Code>{
    let l=1usize<<(n+k); let d=1usize<<n;
    if l>f.q as usize+1 {return None}
    for i in 0..max_tries {
        let seed=start+i as u64;
        let mut c=spark_generator(n,k,f,seed,true);
        if is_mds_generator(&c.gen,l,d,f) {c.checked=true;return Some(c)}
    }
    None
}

fn main(){
    let args=std::env::args().collect::<Vec<_>>();
    let families:usize=args.get(1).and_then(|s|s.parse().ok()).unwrap_or(5);
    let random_trials:usize=args.get(2).and_then(|s|s.parse().ok()).unwrap_or(6);
    let planted_trials:usize=args.get(3).and_then(|s|s.parse().ok()).unwrap_or(3);
    let hill_iters:usize=args.get(4).and_then(|s|s.parse().ok()).unwrap_or(40);

    println!("brief13b_partD_exact families={families} random_trials={random_trials} planted_trials={planted_trials} hill_iters={hill_iters}");
    let cases=[
        (GF{m:3,poly:0b1011,q:8,name:"GF8"},2usize,2usize,true),
        (GF{m:4,poly:0b10011,q:16,name:"GF16"},2usize,2usize,true),
        (GF{m:2,poly:0b111,q:4,name:"GF4"},3usize,2usize,true),
        (GF{m:4,poly:0b10011,q:16,name:"GF16"},2usize,3usize,false), // optional case
    ];

    for (case_ix,(f,n,k,required)) in cases.into_iter().enumerate() {
        if !required && std::env::var("BRIEF13_OPTIONAL").ok().as_deref()!=Some("1") {
            println!("OPTIONAL_SKIPPED field={} n={} k={} set BRIEF13_OPTIONAL=1 to run",f.name,n,k);
            continue
        }
        println!("CASE field={} n={} k={}",f.name,n,k);
        for fam in 0..families {
            let seed=0x13d0_0000u64 ^ ((case_ix as u64)<<24) ^ fam as u64;
            let c=spark_generator(n,k,f,seed,false);
            run_book(book(c),random_trials,planted_trials,hill_iters,seed^0xa5a5);
            let rc=random_linear_code(1usize<<(n+k),1usize<<n,f,seed^0x55aa_1234);
            run_book(book(rc),random_trials,planted_trials,hill_iters,seed^0x5a5a);
        }
        if let Some(c)=find_checked(n,k,f,0x13c0_0000^((case_ix as u64)<<20),1000) {
            println!("CHECKED_FOUND field={} n={} k={} seed={}",f.name,n,k,c.seed);
            run_book(book(c),random_trials,planted_trials,hill_iters,0xc0ffee^case_ix as u64);
        } else {
            println!("CHECKED_NOT_APPLICABLE_OR_NOT_FOUND field={} n={} k={}",f.name,n,k);
        }
    }
}
