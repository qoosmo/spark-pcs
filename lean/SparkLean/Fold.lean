/-
SPARK §4: deterministic folding. A step from layer `i + 1` to `i`
corresponds to the paper's `j = n - i`. All arithmetic is in the challenge
field; base-field structural points may be included by `algebraMap`.
-/
import SparkLean.Gates
import SparkLean.CodeDistance

namespace Spark
universe u v
variable {K : Type u} [Field K] {β : Type v} {i : ℕ}

/-- The ordered pair of symbols in the block above a parent position. -/
def siblingValues (w : Pos β (i + 1) → K) (p : Pos β i) : K × K :=
  (w (p, false), w (p, true))

/-- Fold at challenge `z`, using the two structural points at this layer.
Correct interpolation requires `t p false ≠ t p true` at each parent. -/
def fold (t : Pos β i → Bool → K) (z : K)
    (w : Pos β (i + 1) → K) : Pos β i → K := fun p =>
  w (p, false) + (z - t p false) / (t p true - t p false) *
    (w (p, true) - w (p, false))

/-- Slope of the interpolating affine polynomial at each block. -/
def foldB (t : Pos β i → Bool → K) (w : Pos β (i + 1) → K) : Pos β i → K :=
  fun p => (w (p, true) - w (p, false)) / (t p true - t p false)

/-- Constant coefficient of the interpolating affine polynomial at each block. -/
def foldA (t : Pos β i → Bool → K) (w : Pos β (i + 1) → K) : Pos β i → K :=
  fun p => w (p, false) - t p false * foldB t w p

/-- Evaluate the affine coefficient words at the two structural points. -/
def joinWord (t : Pos β i → Bool → K) (a b : Pos β i → K) : Pos β (i + 1) → K :=
  fun p => a p.1 + t p.1 p.2 * b p.1

/-- The affine line formula. The algebraic identity itself needs no separation assumption. -/
theorem fold_line (t : Pos β i → Bool → K) (z : K) (w : Pos β (i + 1) → K) :
    fold t z w = foldA t w + z • foldB t w := by
  funext p
  simp only [fold, foldA, foldB, Pi.add_apply, Pi.smul_apply, smul_eq_mul, div_eq_mul_inv]
  ring

/-- Interpolation recovers the affine value, by the verified §2 interpolation lemma. -/
theorem fold_joinWord (t : Pos β i → Bool → K)
    (ht : ∀ p, t p false ≠ t p true) (z : K) (a b : Pos β i → K) :
    fold t z (joinWord t a b) = a + z • b := by
  funext p
  simpa only [fold, joinWord, Pi.add_apply, Pi.smul_apply, smul_eq_mul] using
    (Gate.affine_interp (ht p) (a p) (b p) z).symm

/-- Compatibility at exactly layer `i + 1`: no separation assumptions on other layers. -/
theorem fold_enc (T : (j : ℕ) → Pos β j → Bool → K)
    (hT : ∀ p, T i p false ≠ T i p true) (z : K) (u v : ML K i) :
    fold (T i) z (enc T (show ML K (i + 1) from (u, v))) =
      enc T (ML.add u (ML.smul z v)) := by
  have h := fold_joinWord (T i) hT z (enc T u) (enc T v)
  change fold (T i) z (enc T (show ML K (i + 1) from (u, v))) = _ at h
  rw [h]
  funext p
  simp only [Pi.add_apply, Pi.smul_apply, smul_eq_mul, enc_add, enc_smul]

/-- Gate inversion recovers the slope word. -/
theorem foldB_joinWord (t : Pos β i → Bool → K)
    (ht : ∀ p, t p false ≠ t p true) (a b : Pos β i → K) :
    foldB t (joinWord t a b) = b := by
  funext p
  have hd := sub_ne_zero.mpr (ht p).symm
  dsimp [foldB, joinWord]
  field_simp
  ring

/-- Gate inversion recovers the constant coefficient word. -/
theorem foldA_joinWord (t : Pos β i → Bool → K)
    (ht : ∀ p, t p false ≠ t p true) (a b : Pos β i → K) :
    foldA t (joinWord t a b) = a := by
  funext p
  simp only [foldA, foldB_joinWord t ht, joinWord]
  ring

/-- Every word is reconstructed from its unique interpolating coefficients. -/
theorem joinWord_foldAB (t : Pos β i → Bool → K)
    (ht : ∀ p, t p false ≠ t p true) (w : Pos β (i + 1) → K) :
    joinWord t (foldA t w) (foldB t w) = w := by
  funext p
  rcases p with ⟨p, bit⟩
  have hd := sub_ne_zero.mpr (ht p).symm
  cases bit <;> dsimp [joinWord, foldA, foldB] <;> field_simp <;> ring

/-- The paper's bijection between a word and its two affine coefficient words. -/
def foldLineEquiv (t : Pos β i → Bool → K) (ht : ∀ p, t p false ≠ t p true) :
    (Pos β (i + 1) → K) ≃ ((Pos β i → K) × (Pos β i → K)) where
  toFun w := (foldA t w, foldB t w)
  invFun ab := joinWord t ab.1 ab.2
  left_inv := joinWord_foldAB t ht
  right_inv ab := Prod.ext (foldA_joinWord t ht ab.1 ab.2) (foldB_joinWord t ht ab.1 ab.2)

/-- Any interpolating coefficient words must be the ones given by gate inversion. -/
theorem fold_coefficients_unique (t : Pos β i → Bool → K)
    (ht : ∀ p, t p false ≠ t p true) (w : Pos β (i + 1) → K)
    {a b : Pos β i → K} (h : joinWord t a b = w) :
    a = foldA t w ∧ b = foldB t w := by
  rw [← h, foldA_joinWord t ht, foldB_joinWord t ht]
  exact ⟨rfl, rfl⟩

/-- Structural points supplied by an actual gate at each parent. -/
def nodeGatePoints (G : Pos β i → Gate K) (p : Pos β i) (b : Bool) : K :=
  if b then (G p).t1 else (G p).t0

lemma nodeGatePoints_distinct (G : Pos β i → Gate K) (p : Pos β i) :
    nodeGatePoints G p false ≠ nodeGatePoints G p true :=
  (G p).t0_ne_t1

/-- The fold is also the weight form of the verified §2 gate rule. -/
theorem fold_gate_weights (G : Pos β i → Gate K) (z : K)
    (w : Pos β (i + 1) → K) (p : Pos β i) :
    fold (nodeGatePoints G) z w p =
      ((G p).WL z * ((G p).d / (G p).det)) * w (p, true) -
      ((G p).WR z * ((G p).c / (G p).det)) * w (p, false) := by
  have hr := joinWord_foldAB (nodeGatePoints G) (nodeGatePoints_distinct G) w
  have h0 := congrFun hr (p, false)
  have h1 := congrFun hr (p, true)
  simp only [joinWord, nodeGatePoints, Bool.false_eq_true, ite_false, ite_true] at h0 h1
  rw [fold_line]
  change foldA (nodeGatePoints G) w p + z * foldB (nodeGatePoints G) w p = _
  rw [← h0, ← h1]
  exact (G p).gate_rule_weights (foldA (nodeGatePoints G) w p)
    (foldB (nodeGatePoints G) w p) z

/-- Block agreement is exactly simultaneous agreement of the affine coefficients. -/
theorem fold_block_agreement_iff (t : Pos β i → Bool → K)
    (ht : ∀ p, t p false ≠ t p true) (w : Pos β (i + 1) → K)
    (a b : Pos β i → K) (p : Pos β i) :
    siblingValues w p = siblingValues (joinWord t a b) p ↔
      (foldA t w p, foldB t w p) = (a p, b p) := by
  constructor
  · intro h
    have h0 := congrArg Prod.fst h
    have h1 := congrArg Prod.snd h
    change w (p, false) = joinWord t a b (p, false) at h0
    change w (p, true) = joinWord t a b (p, true) at h1
    apply Prod.ext
    · calc
        foldA t w p = foldA t (joinWord t a b) p := by
          dsimp [foldA, foldB]
          rw [h0, h1]
        _ = a p := congrFun (foldA_joinWord t ht a b) p
    · calc
        foldB t w p = foldB t (joinWord t a b) p := by
          dsimp [foldB]
          rw [h0, h1]
        _ = b p := congrFun (foldB_joinWord t ht a b) p
  · intro h
    have ha := congrArg Prod.fst h
    have hb := congrArg Prod.snd h
    change foldA t w p = a p at ha
    change foldB t w p = b p at hb
    calc
      siblingValues w p = siblingValues (joinWord t (foldA t w) (foldB t w)) p :=
        congrArg (fun x => siblingValues x p) (joinWord_foldAB t ht w).symm
      _ = siblingValues (joinWord t a b) p := by
        simp only [siblingValues, joinWord]
        rw [ha, hb]

/-- Joining two lower codewords gives an upper codeword. -/
theorem joinWord_mem_gateCode (T : (j : ℕ) → Pos β j → Bool → K)
    {a b : Pos β i → K} (ha : a ∈ gateCode T i) (hb : b ∈ gateCode T i) :
    joinWord (T i) a b ∈ gateCode T (i + 1) := by
  obtain ⟨u, rfl⟩ := ha
  obtain ⟨v, rfl⟩ := hb
  exact ⟨(u, v), rfl⟩

/-- The codeword and exact block-agreement assertion of the line-form lemma. -/
theorem fold_line_codeword (T : (j : ℕ) → Pos β j → Bool → K)
    (hT : ∀ p, T i p false ≠ T i p true) (w : Pos β (i + 1) → K)
    {a b : Pos β i → K} (ha : a ∈ gateCode T i) (hb : b ∈ gateCode T i) :
    ∃ c ∈ gateCode T (i + 1), ∀ p,
      siblingValues w p = siblingValues c p ↔ (foldA (T i) w p, foldB (T i) w p) = (a p, b p) :=
  ⟨joinWord (T i) a b, joinWord_mem_gateCode T ha hb, fold_block_agreement_iff (T i) hT w a b⟩

/-- Number of differing sibling pairs; a block counts once if either symbol differs. -/
noncomputable def blockHammingDistance [Fintype β]
    (w w' : Pos β (i + 1) → K) : ℕ := by
  classical
  exact hammingDist (siblingValues w) (siblingValues w')

/-- Relative position distance, with the same normalization as the paper. -/
noncomputable def positionDistance [Fintype β] {j : ℕ} (w w' : Pos β j → K) : ℚ :=
  (hammingDistance w w' : ℚ) / Fintype.card (Pos β j)

/-- Paper's block metric: divide the number of unequal pairs by the number of parents,
not by the number of individual symbols. For an empty root type the value is zero. -/
noncomputable def blockDistance [Fintype β] (w w' : Pos β (i + 1) → K) : ℚ :=
  (blockHammingDistance w w' : ℚ) / Fintype.card (Pos β i)

/-- A differing output symbol requires a differing input block. No point-separation
assumption is needed for this locality statement. -/
theorem fold_hammingDistance_le_blocks [Fintype β]
    (t : Pos β i → Bool → K) (z : K) (w w' : Pos β (i + 1) → K) :
    hammingDistance (fold t z w) (fold t z w') ≤ blockHammingDistance w w' := by
  classical
  exact hammingDist_comp_le_hammingDist
    (fun p (s : K × K) => s.1 + (z - t p false) / (t p true - t p false) * (s.2 - s.1))
    (x := siblingValues w) (y := siblingValues w')

/-- §4 Contraction: relative output position distance is at most input block distance. -/
theorem fold_contraction [Fintype β]
    (t : Pos β i → Bool → K) (z : K) (w w' : Pos β (i + 1) → K) :
    positionDistance (fold t z w) (fold t z w') ≤ blockDistance w w' := by
  unfold positionDistance blockDistance
  apply div_le_div_of_nonneg_right _ (by positivity)
  exact_mod_cast fold_hammingDistance_le_blocks t z w w'

/-- Evaluation respects the existing recursive addition. -/
lemma ML.eval_add : ∀ {j : ℕ} (u v : ML K j) (r : Fin j → K),
    ML.eval (ML.add u v) r = ML.eval u r + ML.eval v r
  | 0, u, v, r => rfl
  | j + 1, u, v, r => by
    simp only [ML.eval, ML.add, ML.eval_add]
    ring

/-- Evaluation respects the existing recursive scalar multiplication. -/
lemma ML.eval_smul (z : K) : ∀ {j : ℕ} (u : ML K j) (r : Fin j → K),
    ML.eval (ML.smul z u) r = z * ML.eval u r
  | 0, u, r => rfl
  | j + 1, u, r => by
    simp only [ML.eval, ML.smul, ML.eval_smul]
    ring

/-- Fold all layers, consuming challenges in outer-variable order. -/
def foldAll (T : (j : ℕ) → Pos β j → Bool → K) :
    {j : ℕ} → (Fin j → K) → (Pos β j → K) → (β → K)
  | 0, _, w => w
  | j + 1, r, w => foldAll T (Fin.tail r) (fold (T j) (r 0) w)

/-- The consequence in §4 Compatibility: full folding yields the constant evaluation word. -/
theorem foldAll_enc (T : (j : ℕ) → Pos β j → Bool → K)
    (hT : ∀ j p, T j p false ≠ T j p true) :
    ∀ {j : ℕ} (P : ML K j) (r : Fin j → K),
      foldAll T r (enc T P) = fun _ => ML.eval P r
  | 0, P, r => rfl
  | j + 1, P, r => by
    change foldAll T (Fin.tail r)
      (fold (T j) (r 0) (enc T (show ML K (j + 1) from (P.1, P.2)))) = _
    rw [fold_enc T (hT j), foldAll_enc T hT]
    simp only [ML.eval_add, ML.eval_smul, ML.eval]

section CoefficientMap
variable {F : Type*} [Field F]

/-- Coefficientwise inclusion (or any field homomorphism) on recursive polynomials. -/
def ML.map (f : F →+* K) : {j : ℕ} → ML F j → ML K j
  | 0, c => f c
  | _ + 1, P => (ML.map f P.1, ML.map f P.2)

/-- Encoding commutes with mapping both coefficients and structural points. -/
theorem enc_map (f : F →+* K) (T : (j : ℕ) → Pos β j → Bool → F) :
    ∀ {j : ℕ} (P : ML F j) (p : Pos β j),
      enc (fun j p b => f (T j p b)) (ML.map f P) p = f (enc T P p)
  | 0, P, p => rfl
  | j + 1, P, p => by
    simp only [enc, ML.map, enc_map f T, map_add, map_mul]

/-- Compatibility for base-field words and an arbitrary extension-field challenge.
For the paper use `f = algebraMap F K`; point separation is preserved by injectivity. -/
theorem fold_enc_map (f : F →+* K) (T : (j : ℕ) → Pos β j → Bool → F)
    (hT : ∀ p, T i p false ≠ T i p true) (z : K) (u v : ML F i) :
    fold (fun p b => f (T i p b)) z
        (fun p => f (enc T (show ML F (i + 1) from (u, v)) p)) =
      enc (fun j p b => f (T j p b)) (ML.add (ML.map f u) (ML.smul z (ML.map f v))) := by
  have he := funext (fun p => (enc_map f T (show ML F (i + 1) from (u, v)) p).symm)
  rw [he]
  exact fold_enc (fun j p b => f (T j p b))
    (fun p h => hT p (f.injective h)) z (ML.map f u) (ML.map f v)

end CoefficientMap

end Spark
