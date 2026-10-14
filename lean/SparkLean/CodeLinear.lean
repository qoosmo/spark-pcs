import SparkLean.CodeWeight

namespace Spark
universe u v
variable {F : Type u} [Field F] {β : Type v}

instance ML.instAddCommGroup : (i : ℕ) → AddCommGroup (ML F i)
  | 0 => inferInstanceAs (AddCommGroup F)
  | i + 1 => by
    letI := ML.instAddCommGroup i
    exact inferInstanceAs (AddCommGroup (ML F i × ML F i))

instance ML.instModule : (i : ℕ) → Module F (ML F i)
  | 0 => inferInstanceAs (Module F F)
  | i + 1 => by
    letI := ML.instModule i
    exact inferInstanceAs (Module F (ML F i × ML F i))

lemma ML.zero_eq : ∀ i, ML.zero (F := F) i = (0 : ML F i)
  | 0 => rfl
  | i + 1 => by
    change (ML.zero (F := F) i, ML.zero (F := F) i) = (0, 0)
    rw [ML.zero_eq]

lemma ML.add_eq : ∀ {i} (p q : ML F i), ML.add p q = p + q
  | 0, p, q => rfl
  | i + 1, p, q => by
    change (ML.add p.1 q.1, ML.add p.2 q.2) = (p.1 + q.1, p.2 + q.2)
    rw [ML.add_eq, ML.add_eq]

lemma ML.smul_eq (a : F) : ∀ {i} (p : ML F i), ML.smul a p = a • p
  | 0, p => rfl
  | i + 1, p => by
    change (ML.smul a p.1, ML.smul a p.2) = (a • p.1, a • p.2)
    rw [ML.smul_eq, ML.smul_eq]

/-- The recursive encoder as a linear map; its range is the gate code. -/
def encLinear (T : (i : ℕ) → Pos β i → Bool → F) (i : ℕ) :
    ML F i →ₗ[F] (Pos β i → F) where
  toFun := enc T
  map_add' p q := by ext ω; simpa only [← ML.add_eq] using enc_add T p q ω
  map_smul' a p := by
    ext ω
    simpa only [← ML.smul_eq, Pi.smul_apply, smul_eq_mul] using enc_smul T a p ω

instance ML.instFiniteDimensional : (i : ℕ) → FiniteDimensional F (ML F i)
  | 0 => inferInstanceAs (FiniteDimensional F F)
  | i + 1 => by
    letI := ML.instFiniteDimensional i
    exact inferInstanceAs (FiniteDimensional F (ML F i × ML F i))

lemma ML.finrank : ∀ i, Module.finrank F (ML F i) = 2 ^ i
  | 0 => by simp [ML]
  | i + 1 => by
    change Module.finrank F (ML F i × ML F i) = _
    rw [Module.finrank_prod, ML.finrank, pow_succ]
    omega

/-- Distinct points at every node imply injectivity, provided a root exists. -/
theorem enc_injective [Nonempty β]
    (T : (i : ℕ) → Pos β i → Bool → F)
    (hT : ∀ i ω, T i ω false ≠ T i ω true) :
    ∀ i, Function.Injective (enc T : ML F i → Pos β i → F)
  | 0 => by
    intro p q h
    exact congrFun h (Classical.choice ‹Nonempty β›)
  | i + 1 => by
    intro p q h
    have hv : enc T p.2 = enc T q.2 := by
      funext ω
      have h0 := congrFun h (show Pos β (i + 1) from (ω, false))
      have h1 := congrFun h (show Pos β (i + 1) from (ω, true))
      simp only [enc] at h0 h1
      have he : (T i ω true - T i ω false) * (enc T p.2 ω - enc T q.2 ω) = 0 := by
        linear_combination h1 - h0
      exact sub_eq_zero.mp ((mul_eq_zero.mp he).resolve_left (sub_ne_zero.mpr (hT i ω).symm))
    have hu : enc T p.1 = enc T q.1 := by
      funext ω
      have h0 := congrFun h (show Pos β (i + 1) from (ω, false))
      simp only [enc] at h0
      rw [congrFun hv ω] at h0
      exact add_right_cancel h0
    exact Prod.ext (enc_injective T hT i hu) (enc_injective T hT i hv)

/-- With one root (`k = 0`), injectivity implies surjectivity by equal finite dimensions. -/
theorem enc_surjective_of_injective [Fintype β] [Unique β]
    (T : (i : ℕ) → Pos β i → Bool → F) (i : ℕ)
    (hinj : Function.Injective (enc T : ML F i → Pos β i → F)) :
    Function.Surjective (enc T : ML F i → Pos β i → F) := by
  apply (LinearMap.injective_iff_surjective_of_finrank_eq_finrank
    (f := encLinear T i) ?_).mp hinj
  rw [ML.finrank, Module.finrank_pi]
  simp [card_pos]

/-- Actual gate families have distinct structural points, so need no injectivity assumption. -/
theorem enc_surjective [Fintype β] [Unique β]
    (T : (i : ℕ) → Pos β i → Bool → F)
    (hT : ∀ i ω, T i ω false ≠ T i ω true) (i : ℕ) :
    Function.Surjective (enc T : ML F i → Pos β i → F) :=
  enc_surjective_of_injective T i (enc_injective T hT i)

end Spark
