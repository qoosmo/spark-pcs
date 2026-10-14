import SparkLean.CodeDistance

namespace Spark
universe u v
variable {F : Type u} [Field F] {ι : Type v} [Fintype ι] [Nonempty ι]

/-- The full word space on a nonempty finite coordinate set has distance one. -/
theorem minimumDistance_top : minimumDistance (⊤ : Submodule F (ι → F)) = 1 := by
  classical
  let p : ι := Classical.choice ‹Nonempty ι›
  let w : ι → F := fun q => if q = p then 1 else 0
  have hn : w ≠ 0 := by
    intro h
    have := congrFun h p
    simp [w] at this
  have hw : wordWeight w = 1 := by
    have he : Finset.univ.filter (fun q : ι => q = p) = {p} := by
      ext q
      simp
    simpa [wordWeight, hammingNorm, w] using congrArg Finset.card he
  apply le_antisymm
  · exact (minimumDistance_le_weight _ (Submodule.mem_top) hn).trans_eq hw
  · apply le_minimumDistance _ ⟨w, Submodule.mem_top, hn⟩
    intro v _ hv
    exact (wordWeight_pos.mpr hv)

variable {β : Type v} [Fintype β] [Unique β]

/-- The rate-one conclusion, stated with the exact linear-algebra assumption. -/
theorem rateOne_of_injective
    (T : (i : ℕ) → Pos β i → Bool → F) (i : ℕ)
    (hinj : Function.Injective (enc T : ML F i → Pos β i → F)) :
    gateCode T i = ⊤ ∧ relativeMinimumDistance (gateCode T i) = 1 / (2 ^ i : ℚ) := by
  have ht : gateCode T i = ⊤ :=
    LinearMap.range_eq_top.mpr (enc_surjective_of_injective T i hinj)
  refine ⟨ht, ?_⟩
  letI : Nonempty (Pos β i) := ⟨((allOnesEquiv i).symm (default : β)).1⟩
  rw [ht, relativeMinimumDistance, minimumDistance_top, card_pos]
  simp

/-- For actual gates, point separation proves injectivity. Hence with `k = 0`
every table is a codeword and the relative distance is exactly `2⁻ⁱ`.
No distance-positivity assumption is used to infer injectivity. -/
theorem rateOne
    (T : (i : ℕ) → Pos β i → Bool → F)
    (hT : ∀ i ω, T i ω false ≠ T i ω true) (i : ℕ) :
    gateCode T i = ⊤ ∧ relativeMinimumDistance (gateCode T i) = 1 / (2 ^ i : ℚ) :=
  rateOne_of_injective T i (enc_injective T hT i)

end Spark
