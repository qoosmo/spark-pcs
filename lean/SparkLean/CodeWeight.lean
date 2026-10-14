/-
SPARK §3: cardinality of the support of the per-layer obstruction.
This is a companion to Code.lean, intentionally leaving the existing definitions unchanged.
Verified with the repository's pinned toolchain.
-/
import SparkLean.Code

namespace Spark

universe u v
variable {F : Type u} [Field F] {β : Type v}

/-- The recursively defined position types are finite whenever `β` is finite. -/
instance instFintypePos [Fintype β] (i : ℕ) : Fintype (Pos β i) := by
  induction i with
  | zero => exact inferInstanceAs (Fintype β)
  | succ i ih =>
      letI : Fintype (Pos β i) := ih
      infer_instance

/-- The subtype consisting of paths with all bits equal to `true` is equivalent
    to the set of roots `β`. -/
def allOnesEquiv : (i : ℕ) → {ω : Pos β i // allOnes ω} ≃ β
  | 0 =>
    { toFun := fun ω => ω.1
      invFun := fun b => ⟨b, trivial⟩
      left_inv := by
        intro ω
        apply Subtype.ext
        rfl
      right_inv := by intro b; rfl }
  | i + 1 =>
    { toFun := fun ω => allOnesEquiv i ⟨ω.1.1, ω.2.2⟩
      invFun := fun b =>
        ⟨(((allOnesEquiv i).symm b).1, true),
         ⟨rfl, (((allOnesEquiv i).symm b).2)⟩⟩
      left_inv := by
        intro ω
        rcases ω with ⟨⟨p, b⟩, h⟩
        cases b with
        | false =>
            exact False.elim (Bool.false_ne_true h.1)
        | true =>
            apply Subtype.ext
            change
              ((((allOnesEquiv i).symm (allOnesEquiv i ⟨p, h.2⟩)).1, true) =
                (p, true))
            rw [Equiv.symm_apply_apply]
      right_inv := by
        intro b
        exact (allOnesEquiv i).right_inv b }

/-- Exactly one all-ones path lies above each root in `β`. -/
theorem card_allOnes [Fintype β] (i : ℕ) :
    (@Fintype.card {ω : Pos β i // allOnes ω}
      (Fintype.ofEquiv β (allOnesEquiv i).symm)) = Fintype.card β := by
  classical
  letI : Fintype {ω : Pos β i // allOnes ω} :=
    Fintype.ofEquiv β (allOnesEquiv i).symm
  exact Fintype.card_congr (allOnesEquiv i)

/-- Hamming weight, defined as the number of nonzero coordinates. -/
noncomputable def hammingWeight [Fintype β] (i : ℕ) (w : Pos β i → F) : ℕ := by
  classical
  letI : Fintype (Pos β i) := instFintypePos i
  exact Fintype.card {ω : Pos β i // w ω ≠ 0}

/-- §3 per-layer obstruction: its Hamming weight is exactly `|β|`. -/
theorem perLayerBad_weight [Fintype β]
    (τ : ℕ → Bool → F) (hτ : ∀ j, τ j false ≠ τ j true) (i : ℕ) :
    hammingWeight (β := β) i (enc (fun j _ b => τ j b) (perLayerBad τ i)) = Fintype.card β := by
  classical
  unfold hammingWeight
  let e : {ω : Pos β i // enc (fun j _ b => τ j b) (perLayerBad τ i) ω ≠ 0} ≃
          {ω : Pos β i // allOnes ω} :=
    { toFun := fun ω => ⟨ω.1, (perLayerBad_ne_zero_iff τ hτ ω.1).mp ω.2⟩
      invFun := fun ω => ⟨ω.1, (perLayerBad_ne_zero_iff τ hτ ω.1).mpr ω.2⟩
      left_inv := by intro ω; apply Subtype.ext; rfl
      right_inv := by intro ω; apply Subtype.ext; rfl }
  letI : Fintype (Pos β i) := instFintypePos i
  letI : Fintype {ω : Pos β i // allOnes ω} :=
    Fintype.ofEquiv β (allOnesEquiv i).symm
  exact (Fintype.card_congr e).trans (card_allOnes i)

/-- The obstruction is a nonzero codeword when there is at least one root. -/
theorem perLayerBad_enc_ne_zero [Nonempty β]
    (τ : ℕ → Bool → F) (hτ : ∀ j, τ j false ≠ τ j true) (i : ℕ) :
    enc (β := β) (fun j _ b => τ j b) (perLayerBad τ i) ≠ 0 := by
  intro h
  obtain ⟨b⟩ := ‹Nonempty β›
  let ω := (allOnesEquiv (β := β) i).symm b
  have hn := (perLayerBad_ne_zero_iff τ hτ ω.1).mpr ω.2
  exact hn (congrFun h ω.1)

/-- The number of coordinates in an encoded word at layer `i`. -/
theorem card_pos [Fintype β] (i : ℕ) :
    (@Fintype.card (Pos β i) (instFintypePos i)) = Fintype.card β * 2 ^ i := by
  induction i with
  | zero =>
      simp only [instFintypePos, Pos, pow_zero, mul_one]
  | succ i ih =>
      letI : Fintype (Pos β i) := instFintypePos i
      have hcard : (@Fintype.card (Pos β (i + 1)) (instFintypePos (i + 1))) =
          (@Fintype.card (Pos β i) (instFintypePos i)) * 2 := by
        simpa only [Fintype.card_bool] using
          (Fintype.card_prod (α := Pos β i) (β := Bool))
      rw [hcard, ih, pow_succ]
      ring

/-- Weight divided by block length is `2^{-i}`. This is an upper bound on
    relative minimum distance, not an equality for the minimum distance. -/
theorem perLayerBad_relative_weight [Fintype β] [Nonempty β]
    (τ : ℕ → Bool → F) (hτ : ∀ j, τ j false ≠ τ j true) (i : ℕ) :
    (hammingWeight (β := β) i (enc (fun j _ b => τ j b) (perLayerBad τ i)) : ℚ) /
       ((@Fintype.card (Pos β i) (instFintypePos i) : ℕ) : ℚ) =
         1 / (2 ^ i : ℚ) := by
  rw [perLayerBad_weight τ hτ i, card_pos]
  have hb : (Fintype.card β : ℚ) ≠ 0 := by
    exact_mod_cast (Fintype.card_ne_zero : Fintype.card β ≠ 0)
  push_cast
  field_simp

end Spark
