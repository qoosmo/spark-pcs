/-
SPARK — Section 3 of the paper: the gate code (first part).
Encoding, closed form `Enc_n(F)(ω) = F(r(ω))`, prefix structure of the points,
encoding cost, and the per-layer obstruction.
-/
import Mathlib

namespace Spark

universe u v

/-- Multilinear polynomials in `i` variables, in recursive form `F = u + x · v`
(the pair `(u, v)`); the outermost variable is coordinate `0`. -/
@[reducible] def ML (F : Type u) : ℕ → Type u
  | 0 => F
  | i + 1 => ML F i × ML F i

/-- Positions `Ω_i = β × {0,1}^i`, with `Ω_{i+1} = Ω_i × {0,1}`, `ω = (ω', b)`.
For the paper, `β = {0,1}^k`. -/
@[reducible] def Pos (β : Type v) : ℕ → Type v
  | 0 => β
  | i + 1 => Pos β i × Bool

variable {F : Type u} [Field F] {β : Type v}

/-- Evaluation of a recursive multilinear polynomial at a point. -/
def ML.eval : {i : ℕ} → ML F i → (Fin i → F) → F
  | 0, c, _ => c
  | _ + 1, p, r => ML.eval p.1 (Fin.tail r) + r 0 * ML.eval p.2 (Fin.tail r)

/-- The zero multilinear polynomial. -/
def ML.zero : (i : ℕ) → ML F i
  | 0 => 0
  | i + 1 => (ML.zero i, ML.zero i)

/-- Coefficientwise addition of recursive multilinear polynomials. -/
def ML.add : {i : ℕ} → ML F i → ML F i → ML F i
  | 0, p, q => p + q
  | _ + 1, p, q => (ML.add p.1 q.1, ML.add p.2 q.2)

/-- Scalar multiple of a recursive multilinear polynomial. -/
def ML.smul (a : F) : {i : ℕ} → ML F i → ML F i
  | 0, c => a * c
  | _ + 1, p => (ML.smul a p.1, ML.smul a p.2)

/-- Encoding (Definition "Encoding"): `T i ω' b` is the structural point `t^b(ω')`
of the gate at node `ω' ∈ Ω_i`, used at level `i+1`. -/
def enc (T : (i : ℕ) → Pos β i → Bool → F) : {i : ℕ} → ML F i → Pos β i → F
  | 0, c, _ => c
  | i + 1, p, ω => enc T p.1 ω.1 + T i ω.1 ω.2 * enc T p.2 ω.1

/-- The evaluation point `r(ω)` attached to a position. -/
def pt (T : (i : ℕ) → Pos β i → Bool → F) : {i : ℕ} → Pos β i → (Fin i → F)
  | 0, _ => fun m => Fin.elim0 m
  | i + 1, ω => Fin.cons (T i ω.1 ω.2) (pt T ω.1)

/-- **Closed form** (Proposition "Closed form"): `Enc_n(F)(ω) = F(r(ω))`. -/
theorem enc_eq_eval (T : (i : ℕ) → Pos β i → Bool → F) :
    ∀ {i : ℕ} (P : ML F i) (ω : Pos β i), enc T P ω = ML.eval P (pt T ω)
  | 0, P, ω => by simp only [enc, ML.eval]
  | i + 1, P, ω => by
      simp only [enc, ML.eval, pt, Fin.tail_cons, Fin.cons_zero,
        enc_eq_eval T P.1 ω.1, enc_eq_eval T P.2 ω.1]

/-- The outer coordinate of `r(ω', b)` is the gate point `t^b(ω')`. -/
lemma pt_zero (T : (i : ℕ) → Pos β i → Bool → F) {i : ℕ} (ω : Pos β (i + 1)) :
    pt T ω 0 = T i ω.1 ω.2 := by
  simp only [pt, Fin.cons_zero]

/-- The inner coordinates of `r(ω', b)` are those of `r(ω')`: they depend only on the prefix. -/
lemma pt_succ (T : (i : ℕ) → Pos β i → Bool → F) {i : ℕ} (ω : Pos β (i + 1)) (m : Fin i) :
    pt T ω m.succ = pt T ω.1 m := by
  simp only [pt, Fin.cons_succ]

/-- Two sibling positions have points that differ only in the outer coordinate. -/
lemma pt_siblings (T : (i : ℕ) → Pos β i → Bool → F) {i : ℕ} (ω' : Pos β i) (m : Fin i) :
    pt T (show Pos β (i + 1) from (ω', false)) m.succ
      = pt T (show Pos β (i + 1) from (ω', true)) m.succ := by
  rw [pt_succ, pt_succ]

/-- Encoding preserves the zero polynomial. -/
lemma enc_zero (T : (i : ℕ) → Pos β i → Bool → F) :
    ∀ {i : ℕ} (ω : Pos β i), enc T (ML.zero i) ω = 0
  | 0, ω => rfl
  | i + 1, ω => by
      simp only [enc, ML.zero, enc_zero T ω.1, mul_zero, add_zero]

/-- Encoding preserves addition for every per-node family of structural points. -/
lemma enc_add (T : (i : ℕ) → Pos β i → Bool → F) :
    ∀ {i : ℕ} (P Q : ML F i) (ω : Pos β i),
      enc T (ML.add P Q) ω = enc T P ω + enc T Q ω
  | 0, P, Q, ω => rfl
  | i + 1, P, Q, ω => by
      simp only [enc, ML.add, enc_add T P.1 Q.1, enc_add T P.2 Q.2]
      ring

/-- The encoding is compatible with scalar multiplication. -/
lemma enc_smul (T : (i : ℕ) → Pos β i → Bool → F) (a : F) :
    ∀ {i : ℕ} (P : ML F i) (ω : Pos β i), enc T (ML.smul a P) ω = a * enc T P ω
  | 0, P, ω => by simp only [enc, ML.smul]
  | i + 1, P, ω => by
      simp only [enc, ML.smul, enc_smul T a P.1, enc_smul T a P.2]
      ring

/-- Cost model (Proposition "Encoding cost"): `T(0) = 2^k`, `T(i+1) = 2 T(i) + L_{i+1}`. -/
def encCost (k : ℕ) : ℕ → ℕ
  | 0 => 2 ^ k
  | i + 1 => 2 * encCost k i + 2 ^ (k + i + 1)

/-- `T(n) = (n+1) 2^{n+k}`. -/
theorem encCost_eq (k i : ℕ) : encCost k i = (i + 1) * 2 ^ (k + i) := by
  induction i with
  | zero => simp [encCost]
  | succ i ih =>
      rw [encCost, ih]
      ring

/-- The polynomial `∏_j (x_j - t_j^0)` for a per-layer family `τ`. -/
def perLayerBad (τ : ℕ → Bool → F) : (i : ℕ) → ML F i
  | 0 => (1 : F)
  | i + 1 => (ML.smul (-τ i false) (perLayerBad τ i), perLayerBad τ i)

/-- All path bits of a position are `1`. -/
def allOnes : {i : ℕ} → Pos β i → Prop
  | 0, _ => True
  | _ + 1, ω => ω.2 = true ∧ allOnes ω.1

/-- **Per-layer obstruction** (Proposition "Per-layer families have distance `2^{-n}`"):
for a per-layer family with distinct points, the encoding of `∏_j (x_j - t_j^0)` is nonzero
exactly at the positions whose path bits are all `1`. -/
theorem perLayerBad_ne_zero_iff (τ : ℕ → Bool → F) (hτ : ∀ i, τ i false ≠ τ i true) :
    ∀ {i : ℕ} (ω : Pos β i),
      enc (fun j _ b => τ j b) (perLayerBad τ i) ω ≠ 0 ↔ allOnes ω
  | 0, ω => by simp [enc, perLayerBad, allOnes]
  | i + 1, ω => by
      have key : enc (fun j _ b => τ j b) (perLayerBad τ (i + 1)) ω
          = (τ i ω.2 - τ i false) * enc (fun j _ b => τ j b) (perLayerBad τ i) ω.1 := by
        simp only [enc, perLayerBad, enc_smul]
        ring
      rw [key, mul_ne_zero_iff, perLayerBad_ne_zero_iff τ hτ ω.1]
      simp only [allOnes]
      cases hb : ω.2
      · simp
      · simp [sub_ne_zero.mpr (hτ i).symm]

end Spark
