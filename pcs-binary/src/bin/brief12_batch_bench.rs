
use spark_binary::{
    encode::GateFamily,
    field::F128,
    merkle_v05::HashKind,
    protocol_batch_v12::prove_and_verify_batch_v12,
    security::soundness_bits_from,
};
use std::time::Duration;

fn med(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a,b| a.partial_cmp(b).unwrap());
    let n=xs.len();
    if n%2==1 { xs[n/2] } else { (xs[n/2-1]+xs[n/2])/2.0 }
}
fn ms(d: Duration)->f64{d.as_secs_f64()*1e3}

fn main(){
    let args=std::env::args().collect::<Vec<_>>();
    let bt=args.get(1).and_then(|x|x.parse::<usize>().ok()).unwrap_or(4);
    let m=args.get(2).and_then(|x|x.parse::<usize>().ok()).unwrap_or(4);
    let runs=args.get(3).and_then(|x|x.parse::<usize>().ok()).unwrap_or(10);
    let n=args.get(4).and_then(|x|x.parse::<usize>().ok()).unwrap_or(20);
    let k=2usize; let g=16u32; let seed=1u64;
    let sec=soundness_bits_from(n,k,128.0,256.0,g as f64,64.0,3);
    let s=sec.s;
    assert!((1usize..=16).contains(&bt));
    assert!([3usize,4].contains(&m));
    assert!(runs>=1);

    let setup_t=std::time::Instant::now();
    let checked=GateFamily::from_seed_checked_i0_3(n,k,seed);
    let setup_ms=setup_t.elapsed().as_secs_f64()*1e3;
    let coeff_len=1usize<<n;
    let coeffs=(0..bt).map(|c|{
        (0..coeff_len).map(|i|{
            let x=(i as u128)
                ^ ((c as u128 + 1) << 80)
                ^ ((i as u128).wrapping_mul(0x9e3779b97f4a7c15u128));
            F128(x)
        }).collect::<Vec<_>>()
    }).collect::<Vec<_>>();

    let mut enc=Vec::new(); let mut c0=Vec::new(); let mut fold=Vec::new(); let mut cf=Vec::new();
    let mut grind=Vec::new(); let mut open=Vec::new(); let mut prov=Vec::new(); let mut ver=Vec::new();
    let mut vgd=Vec::new(); let mut vtr=Vec::new(); let mut vm=Vec::new(); let mut vf=Vec::new(); let mut vo=Vec::new();
    let mut proof_bytes=Vec::new(); let mut field_bytes=Vec::new(); let mut hash_bytes=Vec::new();
    let mut peak=Vec::new();

    for r in 0..runs {
        let out=prove_and_verify_batch_v12(&coeffs,&checked.family,seed,checked.counter,s,g,m,HashKind::Blake3);
        if !out.verified { panic!("batch verification failed on run {r}"); }
        enc.push(ms(out.encode)); c0.push(ms(out.commit0)); fold.push(ms(out.fold_total));
        cf.push(ms(out.commit_folds)); grind.push(ms(out.grind)); open.push(ms(out.query_open));
        prov.push(ms(out.prover_total())); ver.push(ms(out.verify.total()));
        vgd.push(ms(out.verify.gate_derivation)); vtr.push(ms(out.verify.transcript)); vm.push(ms(out.verify.merkle)); vf.push(ms(out.verify.folding)); vo.push(ms(out.verify.other));
        proof_bytes.push(out.proof.serialized_size_bytes() as f64);
        field_bytes.push(out.proof.field_bytes() as f64);
        hash_bytes.push(out.proof.hash_bytes() as f64);
        peak.push(out.peak_memory_estimate_bytes as f64);
        eprintln!("run={} verified=true prover_ms={:.3} verify_ms={:.3} proof_bytes={}",
            r+1,ms(out.prover_total()),ms(out.verify.total()),out.proof.serialized_size_bytes());
    }

    let threads=std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_|"default".into());
    let p=med(prov); let v=med(ver); let pb=med(proof_bytes); let fb=med(field_bytes); let hb=med(hash_bytes); let pk=med(peak);
    println!("brief12b_batch_benchmark");
    println!("n={n} k={k} i0=3 m={m} g={g} s={s} t={bt} runs={runs} threads={threads} hash=BLAKE3");
    println!("delta_code={:.6} delta={:.6} gamma={:.6} M={} N1={} eps_log2={:.3}",sec.delta_code,sec.delta,sec.gamma,sec.m,sec.n1,sec.eps.log2());
    println!("fold_term_bits={:.3} query_term_bits={:.3}",sec.fold_bits,sec.query_bits);
    println!("setup_ms={setup_ms:.3}");
    println!("encode_ms={:.3}",med(enc));
    println!("commit0_ms={:.3}",med(c0));
    println!("fold_ms={:.3}",med(fold));
    println!("commit_folds_ms={:.3}",med(cf));
    println!("grind_ms={:.3}",med(grind));
    println!("openings_ms={:.3}",med(open));
    println!("prover_ms={p:.3}");
    println!("prover_per_poly_ms={:.3}",p/bt as f64);
    println!("verify_ms={v:.3}");
    println!("verify_per_poly_ms={:.3}",v/bt as f64);
    println!("verify_gate_derivation_ms={:.3}",med(vgd));
    println!("verify_transcript_ms={:.3}",med(vtr));
    println!("verify_merkle_ms={:.3}",med(vm));
    println!("verify_folding_ms={:.3}",med(vf));
    println!("verify_other_ms={:.3}",med(vo));
    println!("proof_bytes={}",pb as usize);
    println!("proof_kib={:.3}",pb/1024.0);
    println!("proof_per_poly_kib={:.3}",pb/1024.0/bt as f64);
    println!("field_bytes={}",fb as usize);
    println!("hash_bytes={}",hb as usize);
    println!("nonce_bytes={}",(pb-fb-hb) as usize);
    println!("peak_memory_estimate_bytes={}",pk as usize);
    println!("peak_memory_estimate_gib={:.3}",pk/(1024.0*1024.0*1024.0));
    println!("verified_runs={runs}/{runs}");
}
