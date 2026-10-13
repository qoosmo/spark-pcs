/-
SPARK — Section 2 of the paper: Gates.
First version. Pure algebra over an arbitrary field `F`; the "polynomials independent of x"
of the paper are modelled as vectors in an arbitrary `F`-module `V`.
-/
import Mathlib

namespace Spark

/-- A gate `[[a, b], [c, d]] ∈ GL₂(F)` with `c ≠ 0`, `d ≠ 0` (Definition "Gate"). -/
@[ext]
structure Gate (F : Type*) [Field F] where
  a : F
  b : F
  c : F
  d : F
  hc : c ≠ 0
  hd : d ≠ 0
  hdet : a * d - b * c ≠ 0

namespace Gate

variable {F : Type*} [Field F] (A : Gate F)

/-- Determinant `δ = ad - bc`. -/
def det : F := A.a * A.d - A.b * A.c

/-- Gate weights `W_L(x) = a + c x`, `W_R(x) = b + d x`. -/
def WL (x : F) : F := A.a + A.c * x
def WR (x : F) : F := A.b + A.d * x

/-- Structural points `t⁰ = -a/c`, `t¹ = -b/d`. -/
def t0 : F := -A.a / A.c
def t1 : F := -A.b / A.d

lemma det_ne_zero : A.det ≠ 0 := A.hdet

/-- `δ = c d (t¹ - t⁰)` (Lemma "Gates are point pairs with scales"). -/
lemma det_eq : A.det = A.c * A.d * (A.t1 - A.t0) := by
  have hc := A.hc
  have hd := A.hd
  simp only [det, t0, t1]
  field_simp
  ring

/-- The two structural points are distinct. -/
lemma t0_ne_t1 : A.t0 ≠ A.t1 := by
  intro h
  apply A.det_ne_zero
  rw [det_eq, h, sub_self, mul_zero]

lemma t1_sub_t0_ne_zero : A.t1 - A.t0 ≠ 0 :=
  sub_ne_zero.mpr (Ne.symm A.t0_ne_t1)

/-- The gate with scales `c, d` and structural points `t0 ≠ t1`. -/
def ofPoints (c d p q : F) (hc : c ≠ 0) (hd : d ≠ 0) (hpq : p ≠ q) : Gate F where
  a := -p * c
  b := -q * d
  c := c
  d := d
  hc := hc
  hd := hd
  hdet := by
    have h : (-p * c) * d - (-q * d) * c = c * d * (q - p) := by ring
    rw [h]
    exact mul_ne_zero (mul_ne_zero hc hd) (sub_ne_zero.mpr (Ne.symm hpq))

lemma ofPoints_t0 (c d p q : F) (hc : c ≠ 0) (hd : d ≠ 0) (hpq : p ≠ q) :
    (ofPoints c d p q hc hd hpq).t0 = p := by
  simp only [ofPoints, t0]
  rw [div_eq_iff hc]
  ring

lemma ofPoints_t1 (c d p q : F) (hc : c ≠ 0) (hd : d ≠ 0) (hpq : p ≠ q) :
    (ofPoints c d p q hc hd hpq).t1 = q := by
  simp only [ofPoints, t1]
  rw [div_eq_iff hd]
  ring

/-- Every gate is determined by its scales and structural points (bijectivity, one direction;
the other direction is `ofPoints_t0`, `ofPoints_t1`). -/
lemma eq_ofPoints : A = ofPoints A.c A.d A.t0 A.t1 A.hc A.hd A.t0_ne_t1 := by
  have hc := A.hc
  have hd := A.hd
  ext
  · simp only [ofPoints, t0]; field_simp
  · simp only [ofPoints, t1]; field_simp
  · rfl
  · rfl

variable {V : Type*} [AddCommGroup V] [Module F V]

/-- `F_L = δ⁻¹ (d u - b v)`. -/
def FL (u v : V) : V := A.det⁻¹ • (A.d • u - A.b • v)

/-- `F_R = δ⁻¹ (-c u + a v)`. -/
def FR (u v : V) : V := A.det⁻¹ • ((-A.c) • u + A.a • v)

/-- Decomposition: `u + x v = W_L(x) F_L + W_R(x) F_R` (Lemma "Decomposition and collapse"). -/
theorem decomp (u v : V) (x : F) :
    u + x • v = A.WL x • A.FL u v + A.WR x • A.FR u v := by
  have hδ : A.det ≠ 0 := A.det_ne_zero
  simp only [FL, FR, WL, WR]
  match_scalars <;> field_simp <;> (try simp only [det]) <;> ring

/-- Uniqueness of the decomposition. -/
theorem decomp_unique (u v L R : V)
    (h : ∀ x : F, u + x • v = A.WL x • L + A.WR x • R) :
    L = A.FL u v ∧ R = A.FR u v := by
  have hδ : A.det ≠ 0 := A.det_ne_zero
  have h0 := h 0
  have h1 := h 1
  simp only [WL, WR, zero_smul, add_zero, mul_zero, mul_one, one_smul] at h0 h1
  -- h0 : u = a•L + b•R ;  h1 : u + v = (a+c)•L + (b+d)•R
  have hv : v = A.c • L + A.d • R := by
    have := congrArg (fun w => w - u) h1
    simp only [add_sub_cancel_left] at this
    rw [this, h0]; module
  constructor
  · simp only [FL]; rw [h0, hv]
    match_scalars <;> field_simp <;> (try simp only [det]) <;> ring
  · simp only [FR]; rw [h0, hv]
    match_scalars <;> field_simp <;> (try simp only [det]) <;> ring

/-- Collapse at `t⁰`: `F(t⁰) = γ⁰ F_R`, `γ⁰ = -δ/c`. -/
theorem collapse_t0 (u v : V) :
    u + A.t0 • v = (-A.det / A.c) • A.FR u v := by
  have hc := A.hc
  have hδ : A.det ≠ 0 := A.det_ne_zero
  simp only [FR, t0]
  match_scalars <;> field_simp <;> (try simp only [det]) <;> ring

/-- Collapse at `t¹`: `F(t¹) = γ¹ F_L`, `γ¹ = δ/d`. -/
theorem collapse_t1 (u v : V) :
    u + A.t1 • v = (A.det / A.d) • A.FL u v := by
  have hd := A.hd
  have hδ : A.det ≠ 0 := A.det_ne_zero
  simp only [FL, t1]
  match_scalars <;> field_simp <;> (try simp only [det]) <;> ring

/-- Affine interpolation through two distinct points (field-generic helper). -/
theorem affine_interp {p q : F} (hpq : p ≠ q) (u v : V) (z : F) :
    u + z • v = (u + p • v) + ((z - p) / (q - p)) • ((u + q • v) - (u + p • v)) := by
  have h : q - p ≠ 0 := sub_ne_zero.mpr (Ne.symm hpq)
  match_scalars <;> field_simp <;> ring

/-- Gate rule at an arbitrary point, interpolation form:
`F(z) = w⁰ + (z - t⁰)/(t¹ - t⁰) · (w¹ - w⁰)`. -/
theorem gate_rule (u v : V) (z : F) :
    u + z • v = (u + A.t0 • v) + ((z - A.t0) / (A.t1 - A.t0)) • ((u + A.t1 • v) - (u + A.t0 • v)) :=
  affine_interp A.t0_ne_t1 u v z

/-- Gate rule, weight form: `F(z) = W_L(z) (d/δ) w¹ - W_R(z) (c/δ) w⁰`. -/
theorem gate_rule_weights (u v : V) (z : F) :
    u + z • v = (A.WL z * (A.d / A.det)) • (u + A.t1 • v)
              - (A.WR z * (A.c / A.det)) • (u + A.t0 • v) := by
  have hc := A.hc
  have hd := A.hd
  have hδ : A.det ≠ 0 := A.det_ne_zero
  simp only [WL, WR, t0, t1]
  match_scalars <;> field_simp <;> (try simp only [det]) <;> ring

/-- One-layer sum rule: `∑_{x∈{0,1}} (W_L(x) F_L + W_R(x) F_R) = (2a+c) F_L + (2b+d) F_R`. -/
theorem sum_rule (L R : V) :
    (A.WL 0 • L + A.WR 0 • R) + (A.WL 1 • L + A.WR 1 • R)
      = (2 * A.a + A.c) • L + (2 * A.b + A.d) • R := by
  simp only [WL, WR]
  match_scalars <;> ring

end Gate
end Spark
