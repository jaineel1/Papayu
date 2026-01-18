# Core Intelligence Algorithms

This system uses **deterministic, explainable logic** rather than black-box AI.

## 1. Skill Gap Calculation
For a specific **Target Role** ($R$) and a **User** ($U$):

For each skill $s$ required by $R$:
- Let $L_{req}$ = Required Proficiency (1-5)
- Let $L_{user}$ = User's Proficiency (0 if missing)

$$ \text{Gap}_s = \max(0, L_{req} - L_{user}) $$

If the user has a higher skill level than required, the gap is 0 (not negative).

## 2. Weighted Gap
Not all skills are equal. Critical skills (e.g., "Surgery" for a Doctor) have higher weights than nice-to-haves.

$$ \text{WeightedGap}_s = \text{Gap}_s \times \text{SkillWeight}_s $$

## 3. Readiness Score
The readiness score represents how "ready" a user is for a role, from 0% to 100%.

$$ \text{TotalPossibleWeight} = \sum_{\text{all skills in } R} (\text{RequiredLevel}_s \times \text{SkillWeight}_s) $$

$$ \text{TotalGapWeight} = \sum_{\text{all skills}} \text{WeightedGap}_s $$

$$ \text{Readiness} = 1 - \frac{\text{TotalGapWeight}}{\text{TotalPossibleWeight}} $$

## 4. Ranking
Jobs are ranked by **Readiness Score** (Descending).
Secondary sort: **Total Missing Skills** (Ascending).
