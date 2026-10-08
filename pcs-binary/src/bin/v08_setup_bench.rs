use spark_binary::encode::GateFamily;
use std::time::Instant;

fn med(mut xs:Vec<f64>)->f64{
    xs.sort_by(|a,b|a.partial_cmp(b).unwrap());
    let n=xs.len();
    if n%2==1 {xs[n/2]} else {(xs[n/2-1]+xs[n/2])/2.0}
}
fn main(){
    let a=std::env::args().collect::<Vec<_>>();
    let n=a.get(1).and_then(|x|x.parse::<usize>().ok()).unwrap_or(20);
    let runs=a.get(2).and_then(|x|x.parse::<usize>().ok()).unwrap_or(10);
    let k=2usize; let seed=1u64;

    let mut raw=Vec::new();
    let mut checked=Vec::new();
    let mut counters=Vec::new();

    for _ in 0..runs {
        let t=Instant::now();
        let fam=GateFamily::from_seed(n,k,seed);
        std::hint::black_box(fam.levels.len());
        raw.push(t.elapsed().as_secs_f64()*1e3);

        let t=Instant::now();
        let cs=GateFamily::from_seed_checked_i0_3(n,k,seed);
        std::hint::black_box(cs.family.levels.len());
        checked.push(t.elapsed().as_secs_f64()*1e3);
        counters.push(cs.counter);
    }

    let r=med(raw);
    let c=med(checked);
    println!("v08_setup_benchmark");
    println!("n={n} k={k} i0=3 runs={runs}");
    println!("setup_counter={}",counters[0]);
    println!("gate_derivation_ms={r:.3}");
    println!("setup_checked_total_ms={c:.3}");
    println!("c3_check_residual_ms={:.3}",(c-r).max(0.0));
    println!("note=c3_check_residual is checked-setup total minus unchecked gate derivation");
}
