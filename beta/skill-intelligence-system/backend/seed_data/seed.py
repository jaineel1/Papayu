import json
import os
import sys

# Add parent dir to path to import app
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app import models
from app.database import SessionLocal, engine, Base

# Init DB
Base.metadata.create_all(bind=engine)

def seed():
    db = SessionLocal()
    
    # Load JSON
    with open(os.path.join(os.path.dirname(__file__), 'data.json')) as f:
        data = json.load(f)

    print("Seeding Skills...")
    skill_map = {} # Name -> ID
    for s in data['skills']:
        existing = db.query(models.Skill).filter_by(name=s['name']).first()
        if not existing:
            new_skill = models.Skill(name=s['name'], category=s['category'])
            db.add(new_skill)
            db.commit()
            db.refresh(new_skill)
            skill_map[s['name']] = new_skill.id
        else:
            skill_map[s['name']] = existing.id
            
    print("Seeding Resources...")
    for r in data['resources']:
        skill_id = skill_map.get(r['skill'])
        if skill_id:
            exists = db.query(models.LearningResource).filter_by(title=r['title']).first()
            if not exists:
                res = models.LearningResource(
                    title=r['title'], type=r['type'], provider=r['provider'],
                    skill_id=skill_id, difficulty_level=r['diff'],
                    link=r.get('link')
                )
                db.add(res)
            else:
                # Update existing resource
                exists.type = r['type']
                exists.provider = r['provider']
                exists.difficulty_level = r['diff']
                exists.link = r.get('link')
    db.commit()

    print("Seeding Roles...")
    for role_data in data['roles']:
        role = db.query(models.JobRole).filter_by(title=role_data['title']).first()
        if not role:
            role = models.JobRole(title=role_data['title'], domain=role_data['domain'])
            db.add(role)
            db.commit()
            db.refresh(role)
            
            # Add reqs
            for req in role_data['required_skills']:
                skill_id = skill_map.get(req['skill'])
                if skill_id:
                    js = models.JobSkill(
                        job_role_id=role.id,
                        skill_id=skill_id,
                        required_level=req['level'],
                        importance_weight=req['weight']
                    )
                    db.add(js)
            db.commit()
            
    print("Seeding Demo User...")
    demo_user = db.query(models.User).filter_by(email="demo@skills.ai").first()
    if not demo_user:
        # Firebase Auth usage makes this local hash irrelevant
        hashed_pwd = "firebase_managed_placeholder_hash"
        demo_user = models.User(
            full_name="Alex Chen",
            email="demo@skills.ai",
            current_role_title="Junior Developer",
            password_hash=hashed_pwd
        )
        db.add(demo_user)
        db.commit()

    print("Seeding Projects...")
    if 'projects' in data:
        for p_data in data['projects']:
            proj = db.query(models.Project).filter_by(title=p_data['title']).first()
            if not proj:
                proj = models.Project(
                    title=p_data['title'],
                    description=p_data['description'],
                    difficulty_level=p_data['difficulty'],
                    domain=p_data['domain'],
                    github_repo_url=p_data['repo']
                )
                db.add(proj)
                db.commit()
                db.refresh(proj)
                
                # Add project skills
                for s_name in p_data['skills']:
                    # Fuzzy match or exact match? Exact for now, handle loose naming if needed
                    # Try exact first
                    s_id = skill_map.get(s_name)
                    # If not found, try finding by partial? No, simpler to be strict or ensure data.json matches.
                    # data.json usually matches.
                    
                    if s_id:
                        ps = models.ProjectSkill(
                            project_id=proj.id,
                            skill_id=s_id
                        )
                        db.add(ps)
                db.commit()

    print("Seeding Complete!")
    db.close()

if __name__ == "__main__":
    seed()
