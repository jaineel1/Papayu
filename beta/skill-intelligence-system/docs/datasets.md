# Datasets

## 1. LinkedIn Jobs & Skills
- **Source**: [Kaggle](https://www.kaggle.com/datasets/asaniczka/1-3m-linkedin-jobs-and-skills-2024)
- **Usage**:
  - Extracted **Job Titles** (e.g., "Data Scientist", "Agronomist").
  - Extracted **Skills** list.
  - Used to build the initial `JobRole` and `JobSkill` tables.

## 2. O*NET Skills
- **Source**: [O*NET Center](https://www.onetcenter.org/database.html)
- **Usage**:
  - Skill taxonomy and categorization.
  - Normalizing synonyms (e.g., "coding" -> "programming").

## 3. Synthetic Learning Resources
- **Source**: Generated manually / using scripts.
- **Structure**:
  - `Title`: Name of course/cert.
  - `Type`: Course, Project, Certification.
  - `Skill_ID`: What it teaches.
  - `Difficulty`: Level (Beginner -> Advanced).
