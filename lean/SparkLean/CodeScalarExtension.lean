import SparkLean.CodeDistance

namespace Spark
universe u v w
variable {F : Type u} {K : Type v} [Field F] [Field K] [Algebra F K]
variable {ι : Type w} [Fintype ι]

/-- Coordinatewise inclusion of base-field words. -/
def extendWord (c : ι → F) : ι → K := fun p => algebraMap F K (c p)

/-- Scalar extension of a code: the `K`-linear span of its coordinatewise image.
This realizes `C ⊗[F] K` as a code in `K^ι`. -/
def extendedCode (C : Submodule F (ι → F)) : Submodule K (ι → K) :=
  Submodule.span K (extendWord (K := K) '' (C : Set (ι → F)))

omit [Fintype ι] in
lemma extendWord_mem (C : Submodule F (ι → F)) {c : ι → F} (hc : c ∈ C) :
    extendWord (K := K) c ∈ extendedCode (K := K) C :=
  Submodule.subset_span ⟨c, hc, rfl⟩

omit [Fintype ι] in
lemma extendWord_ne_zero {c : ι → F} (hc : c ≠ 0) :
    extendWord (K := K) c ≠ 0 := by
  intro h
  apply hc
  funext p
  exact (algebraMap F K).injective (by simpa [extendWord] using congrFun h p)

lemma extendWord_weight (c : ι → F) : wordWeight (extendWord (K := K) c) = wordWeight c := by
  classical
  exact hammingNorm_comp (fun _ => algebraMap F K)
    (fun _ => (algebraMap F K).injective) (fun _ => map_zero _)

omit [Fintype ι] in
/-- Every base-field linear functional applied coordinatewise to an extended
word yields a word of the original code. Multiplication by an extension-field
scalar is absorbed into the functional in the span induction. -/
lemma project_mem (C : Submodule F (ι → F)) {w : ι → K}
    (hw : w ∈ extendedCode (K := K) C) (φ : K →ₗ[F] F) :
    (fun p => φ (w p)) ∈ C := by
  have h : ∀ ψ : K →ₗ[F] F, (fun p => ψ (w p)) ∈ C := by
    induction hw using Submodule.span_induction with
    | mem x hx =>
      rcases hx with ⟨c, hc, rfl⟩
      intro ψ
      have he : (fun p => ψ (extendWord (K := K) c p)) = ψ 1 • c := by
        funext p
        simp only [extendWord, Pi.smul_apply, smul_eq_mul]
        rw [show algebraMap F K (c p) = c p • (1 : K) by simp [Algebra.smul_def],
          map_smul, smul_eq_mul, mul_comm]
      rw [he]
      exact C.smul_mem _ hc
    | zero =>
      intro ψ
      simpa only [Pi.zero_apply, map_zero] using C.zero_mem
    | add x y hx hy ihx ihy =>
      intro ψ
      simpa only [Pi.add_apply, map_add] using C.add_mem (ihx ψ) (ihy ψ)
    | smul a x hx ih =>
      intro ψ
      exact ih (ψ.comp (LinearMap.mulLeft F a))
  exact h φ

/-- A nonzero extended word has a nonzero base-field projection with no
larger support. Separation by the algebraic dual uses a vector-space basis,
so no finite-degree assumption on the extension is needed. -/
theorem exists_baseWord_le_weight (C : Submodule F (ι → F)) {w : ι → K}
    (hw : w ∈ extendedCode (K := K) C) (hn : w ≠ 0) :
    ∃ c ∈ C, c ≠ 0 ∧ wordWeight c ≤ wordWeight w := by
  classical
  obtain ⟨p, hp⟩ : ∃ p, w p ≠ 0 := by
    by_contra h
    apply hn
    funext p
    simpa using not_exists.mp h p
  obtain ⟨φ, hφ⟩ : ∃ φ : K →ₗ[F] F, φ (w p) ≠ 0 := by
    by_contra h
    apply hp
    apply (Module.forall_dual_apply_eq_zero_iff F (w p)).mp
    intro φ
    simpa using not_exists.mp h φ
  refine ⟨fun p => φ (w p), project_mem C hw φ, ?_, ?_⟩
  · intro h
    exact hφ (congrFun h p)
  · exact hammingNorm_comp_le_hammingNorm (fun _ => φ) (fun _ => map_zero φ)

omit [Fintype ι] in
@[simp] lemma extendedCode_bot : extendedCode (K := K) (⊥ : Submodule F (ι → F)) = ⊥ := by
  apply le_antisymm _ bot_le
  apply Submodule.span_le.mpr
  rintro _ ⟨c, hc, rfl⟩
  have hc0 : c = 0 := hc
  change extendWord (K := K) c = 0
  rw [hc0]
  funext p
  exact map_zero (algebraMap F K)

/-- Scalar extension cannot increase minimum distance: embedded words retain weight. -/
theorem extendedCode_minimumDistance_le (C : Submodule F (ι → F)) :
    minimumDistance (extendedCode (K := K) C) ≤ minimumDistance C := by
  by_cases hC : C = ⊥
  · simp [hC]
  apply le_minimumDistance C (C.ne_bot_iff.mp hC)
  intro c hc hn
  exact (minimumDistance_le_weight _ (extendWord_mem C hc)
    (extendWord_ne_zero (K := K) hn)).trans_eq (extendWord_weight (K := K) c)

/-- Scalar extension cannot decrease minimum distance: project a nonzero word. -/
theorem minimumDistance_le_extendedCode (C : Submodule F (ι → F)) :
    minimumDistance C ≤ minimumDistance (extendedCode (K := K) C) := by
  by_cases hC : C = ⊥
  · simp [hC]
  obtain ⟨c, hc, hn⟩ := C.ne_bot_iff.mp hC
  apply le_minimumDistance _ ⟨extendWord (K := K) c, extendWord_mem C hc, extendWord_ne_zero hn⟩
  intro w hw hne
  obtain ⟨v, hv, hvn, hle⟩ := exists_baseWord_le_weight C hw hne
  exact (minimumDistance_le_weight C hv hvn).trans hle

/-- Extension of scalars preserves absolute minimum distance. -/
theorem extendedCode_minimumDistance (C : Submodule F (ι → F)) :
    minimumDistance (extendedCode (K := K) C) = minimumDistance C :=
  le_antisymm (extendedCode_minimumDistance_le C) (minimumDistance_le_extendedCode C)

/-- Extension of scalars preserves relative minimum distance. -/
theorem extendedCode_relativeMinimumDistance (C : Submodule F (ι → F)) :
    relativeMinimumDistance (extendedCode (K := K) C) = relativeMinimumDistance C := by
  simp only [relativeMinimumDistance, extendedCode_minimumDistance]

/-- In particular, scalar extension preserves the distance of the encoder's image. -/
theorem gateCode_scalarExtension_distance {β : Type w} [Fintype β]
    (T : (i : ℕ) → Pos β i → Bool → F) (i : ℕ) :
    relativeMinimumDistance (extendedCode (K := K) (gateCode T i)) =
      relativeMinimumDistance (gateCode T i) :=
  extendedCode_relativeMinimumDistance (gateCode T i)

end Spark
