from sqlalchemy.orm import Session
from app import models, schemas
from typing import List

def calculate_readiness(user_skills_map: dict, job_role: models.JobRole, db: Session) -> schemas.RoleReadiness:
    """
    Core Algorithm:
    Gap = max(0, required - user)
    Weighted Gap = Gap * Importance
    Readiness = 1 - (Total Weighted Gap / Max Possible Weighted Score)
    """
    total_weighted_gap = 0.0
    total_possible_weight = 0.0
    gaps = []
    missing_count = 0

    for req in job_role.required_skills:
        # Scale: 1-5. Importance: 1.0-5.0 usually.
        # Max possible "score" for this skill component is (ReqLevel * Importance)
        # This represents the "volume" of skill needed.
        # Actually, if I match perfectly, gap is 0.
        # So "Total Requirements Volume" = sum(req.required_level * req.importance_weight)
        
        max_skill_value = req.required_level * req.importance_weight
        total_possible_weight += max_skill_value
        
        user_level = user_skills_map.get(req.skill_id, 0)
        
        gap = max(0, req.required_level - user_level)
        weighted_gap = gap * req.importance_weight
        total_weighted_gap += weighted_gap
        
        if gap > 0:
            missing_count += 1
            # Find resources
            resources = db.query(models.LearningResource).filter(
                models.LearningResource.skill_id == req.skill_id
            ).all() # Simple fetch, could rank by difficulty
            
            res_schemas = [
                schemas.ResourceRecommendation(
                    title=r.title, type=r.type, provider=r.provider, 
                    link=r.link, difficulty_level=r.difficulty_level
                ) for r in resources
            ]
            
            gaps.append(schemas.GapDetail(
                skill_id=req.skill_id,
                skill_name=req.skill.name,
                current_level=user_level,
                required_level=req.required_level,
                gap=gap,
                importance=req.importance_weight,
                recommended_resources=res_schemas
            ))
            
    # Avoid division by zero
    if total_possible_weight == 0:
        readiness = 1.0 # No requirements? Ready!
    else:
        readiness = 1.0 - (total_weighted_gap / total_possible_weight)
        
    return schemas.RoleReadiness(
        role_id=job_role.id,
        role_title=job_role.title,
        domain=job_role.domain,
        readiness_score=max(0.0, readiness), # clamp to 0 just in case
        missing_skill_count=missing_count,
        gaps=gaps
    )

def get_role_recommendations(user_id: int, db: Session) -> List[schemas.RoleReadiness]:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return []
    
    # Map user skills for O(1) lookup
    user_skills_map = {us.skill_id: us.proficiency_level for us in user.skills}
    
    all_roles = db.query(models.JobRole).all()
    results = []
    
    for role in all_roles:
        results.append(calculate_readiness(user_skills_map, role, db))
        
    # Sort by Readiness Descending
    results.sort(key=lambda x: x.readiness_score, reverse=True)
    
    return results

def simulate_readiness(request: schemas.SimulationRequest, db: Session) -> schemas.SimulationResponse:
    user = db.query(models.User).filter(models.User.id == request.user_id).first()
    role = db.query(models.JobRole).filter(models.JobRole.id == request.role_id).first()
    skill = db.query(models.Skill).filter(models.Skill.id == request.skill_id).first()

    if not user or not role or not skill:
        return None

    # Base State
    user_skills_map = {us.skill_id: us.proficiency_level for us in user.skills}
    base_result = calculate_readiness(user_skills_map, role, db)

    # Simulated State
    simulated_map = user_skills_map.copy()
    simulated_map[request.skill_id] = request.target_level
    
    sim_result = calculate_readiness(simulated_map, role, db)

    return schemas.SimulationResponse(
        current_readiness=base_result.readiness_score,
        new_readiness=sim_result.readiness_score,
        improvement=sim_result.readiness_score - base_result.readiness_score,
        skill_simulated=skill.name
    )

def get_project_recommendations(user_id: int, db: Session) -> List[schemas.Project]:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return []

    user_skill_ids = {us.skill_id for us in user.skills}
    
    all_projects = db.query(models.Project).all()
    results = []
    
    for proj in all_projects:
        # Calculate overlap
        req_skills = proj.required_skills
        if not req_skills:
            continue
            
        match_count = 0
        current_project_skill_ids = []
        
        for ps in req_skills:
            if ps.skill_id in user_skill_ids:
                match_count += 1
            # Build schema structure
            current_project_skill_ids.append(
                schemas.ProjectSkillBase(skill_id=ps.skill_id, skill_name=ps.skill.name)
            )
            
        # Relevance Score: Simple overlap percentage or count?
        # User requested: "relevance = number of matching skills / total project skills"
        total_req = len(req_skills)
        relevance = match_count / total_req if total_req > 0 else 0
        
        # Only include if at least 1 skill matches (Eligibility Rule)
        if match_count > 0:
            # We need to map model -> schema manually or rely on from_attributes
            # Pydantic from_attributes works, but we need to inject calculated fields.
            
            p_schema = schemas.Project(
                id=proj.id,
                title=proj.title,
                description=proj.description,
                domain=proj.domain,
                difficulty_level=proj.difficulty_level,
                github_repo_url=proj.github_repo_url,
                required_skills=current_project_skill_ids,
                relevance_score=relevance,
                match_count=match_count
            )
            results.append(p_schema)
            
    # Sort by Relevance Descending
    results.sort(key=lambda x: x.relevance_score, reverse=True)
    
    return results

