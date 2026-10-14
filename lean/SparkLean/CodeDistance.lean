import SparkLean.CodeLinear

namespace Spark
universe u v
variable {F : Type u} [Field F] {ι : Type v} [Fintype ι]

/-- Hamming weight on an arbitrary finite coordinate type. -/
noncomputable def wordWeight (w : ι → F) : ℕ := by
  classical
  exact hammingNorm w

/-- Hamming distance counts coordinates at which two words differ. -/
noncomputable def hammingDistance (x y : ι → F) : ℕ := by
  classical
  exact hammingDist x y

lemma hammingDistance_eq_weight_sub (x y : ι → F) :
    hammingDistance x y = wordWeight (x - y) := by
  classical
  exact hammingDist_eq_hammingNorm x y

lemma wordWeight_pos {w : ι → F} : 0 < wordWeight w ↔ w ≠ 0 := by
  classical
  exact hammingNorm_pos_iff

lemma wordWeight_le_card (w : ι → F) : wordWeight w ≤ Fintype.card ι := by
  classical
  exact hammingNorm_le_card_fintype

/-- Minimum nonzero weight of a linear code. The zero code has distance zero
by the natural-number `sInf ∅` convention. -/
noncomputable def minimumDistance (C : Submodule F (ι → F)) : ℕ :=
  sInf {d | ∃ w ∈ C, w ≠ 0 ∧ wordWeight w = d}

/-- Relative minimum distance, with value zero also for length zero. -/
noncomputable def relativeMinimumDistance (C : Submodule F (ι → F)) : ℚ :=
  (minimumDistance C : ℚ) / Fintype.card ι

lemma minimumDistance_le_weight (C : Submodule F (ι → F))
    {w : ι → F} (hw : w ∈ C) (hn : w ≠ 0) :
    minimumDistance C ≤ wordWeight w :=
  csInf_le ⟨0, fun _ _ => Nat.zero_le _⟩ ⟨w, hw, hn, rfl⟩

lemma le_minimumDistance (C : Submodule F (ι → F)) {d : ℕ}
    (hne : ∃ w ∈ C, w ≠ 0)
    (h : ∀ w ∈ C, w ≠ 0 → d ≤ wordWeight w) : d ≤ minimumDistance C := by
  apply le_csInf
  · obtain ⟨w, hw, hn⟩ := hne
    exact ⟨wordWeight w, w, hw, hn, rfl⟩
  · rintro b ⟨w, hw, hn, rfl⟩
    exact h w hw hn

@[simp] lemma minimumDistance_bot : minimumDistance (⊥ : Submodule F (ι → F)) = 0 := by
  simp [minimumDistance]

/-- A nonzero code attains its minimum at a nonzero word, even over an infinite field. -/
lemma minimumDistance_attained (C : Submodule F (ι → F)) (hC : C ≠ ⊥) :
    ∃ w ∈ C, w ≠ 0 ∧ wordWeight w = minimumDistance C := by
  apply Nat.sInf_mem (s := {d | ∃ w ∈ C, w ≠ 0 ∧ wordWeight w = d})
  obtain ⟨w, hw, hn⟩ := C.ne_bot_iff.mp hC
  exact ⟨wordWeight w, w, hw, hn, rfl⟩

/-- For linear codes, nonzero weights and distances of distinct codewords
have exactly the same possible values. -/
lemma distance_values (C : Submodule F (ι → F)) :
    {d | ∃ w ∈ C, w ≠ 0 ∧ wordWeight w = d} =
    {d | ∃ x ∈ C, ∃ y ∈ C, x ≠ y ∧ hammingDistance x y = d} := by
  ext d
  constructor
  · rintro ⟨w, hw, hn, rfl⟩
    exact ⟨w, hw, 0, C.zero_mem, hn, by rw [hammingDistance_eq_weight_sub, sub_zero]⟩
  · rintro ⟨x, hx, y, hy, hn, rfl⟩
    exact ⟨x - y, C.sub_mem hx hy, sub_ne_zero.mpr hn, (hammingDistance_eq_weight_sub x y).symm⟩

variable {β : Type v} [Fintype β]

lemma wordWeight_eq_hammingWeight (i : ℕ) (w : Pos β i → F) :
    wordWeight w = hammingWeight i w := by
  classical
  simp [wordWeight, hammingNorm, hammingWeight, Fintype.card_subtype]

/-- The gate code is precisely the image of the recursive encoder. -/
def gateCode (T : (i : ℕ) → Pos β i → Bool → F) (i : ℕ) :
    Submodule F (Pos β i → F) := LinearMap.range (encLinear T i)

/-- The paper's per-layer obstruction gives an upper bound, not an equality. -/
theorem perLayer_minimumDistance_le [Nonempty β]
    (τ : ℕ → Bool → F) (hτ : ∀ j, τ j false ≠ τ j true) (i : ℕ) :
    relativeMinimumDistance (gateCode (β := β) (fun j _ b => τ j b) i) ≤
      1 / (2 ^ i : ℚ) := by
  have h := minimumDistance_le_weight
    (gateCode (β := β) (fun j _ b => τ j b) i)
    (w := enc (fun j _ b => τ j b) (perLayerBad τ i))
    ⟨perLayerBad τ i, rfl⟩ (perLayerBad_enc_ne_zero τ hτ i)
  rw [relativeMinimumDistance, ← perLayerBad_relative_weight (β := β) τ hτ i]
  apply div_le_div_of_nonneg_right _ (by positivity)
  exact_mod_cast (h.trans_eq (wordWeight_eq_hammingWeight i _))

/-- Every word is a codeword at rate one for distinct-point gate families. -/
theorem gateCode_eq_top [Unique β]
    (T : (i : ℕ) → Pos β i → Bool → F)
    (hT : ∀ i ω, T i ω false ≠ T i ω true) (i : ℕ) :
    gateCode T i = ⊤ := LinearMap.range_eq_top.mpr (enc_surjective T hT i)

end Spark
