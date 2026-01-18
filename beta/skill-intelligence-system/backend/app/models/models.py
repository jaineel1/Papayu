from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Float, Text
from sqlalchemy.orm import relationship
from ..database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String, nullable=True)
    current_role_title = Column(String, nullable=True) # e.g. "Student"
    
    # Relationships
    skills = relationship("UserSkill", back_populates="user")
    # For simplicity, we can store target_role_id in frontend or separate table, 
    # but let's persist it here for "statefullness"
    target_role_id = Column(Integer, ForeignKey("job_roles.id"), nullable=True)
    target_role = relationship("JobRole", back_populates="interested_users")


class Skill(Base):
    __tablename__ = "skills"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    category = Column(String, index=True) # e.g. "Technical", "Soft Skill"
    
    user_skills = relationship("UserSkill", back_populates="skill")
    job_skills = relationship("JobSkill", back_populates="skill")
    learning_resources = relationship("LearningResource", back_populates="skill")


class JobRole(Base):
    __tablename__ = "job_roles"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, unique=True, index=True)
    domain = Column(String, index=True) # "Healthcare", "AgriTech", "SmartCity"
    description = Column(Text, nullable=True)
    
    required_skills = relationship("JobSkill", back_populates="job_role")
    interested_users = relationship("User", back_populates="target_role")


class JobSkill(Base):
    __tablename__ = "job_skills"

    id = Column(Integer, primary_key=True, index=True)
    job_role_id = Column(Integer, ForeignKey("job_roles.id"))
    skill_id = Column(Integer, ForeignKey("skills.id"))
    
    # 1-5 scale
    required_level = Column(Integer, default=1) 
    # Weight 1.0 = standard, 2.0 = critical
    importance_weight = Column(Float, default=1.0) 

    job_role = relationship("JobRole", back_populates="required_skills")
    skill = relationship("Skill", back_populates="job_skills")


class UserSkill(Base):
    __tablename__ = "user_skills"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    skill_id = Column(Integer, ForeignKey("skills.id"))
    
    proficiency_level = Column(Integer, default=1) # 1-5

    user = relationship("User", back_populates="skills")
    skill = relationship("Skill", back_populates="user_skills")


class LearningResource(Base):
    __tablename__ = "learning_resources"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    type = Column(String) # "Course", "Project", "Certification"
    provider = Column(String) # "Coursera", "EdX", "Internal"
    link = Column(String, nullable=True)
    
    skill_id = Column(Integer, ForeignKey("skills.id"))
    
    # How much this resource helps (roughly maps to level gain)
    difficulty_level = Column(Integer, default=1) 

    skill = relationship("Skill", back_populates="learning_resources")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    domain = Column(String, index=True)
    difficulty_level = Column(Integer, default=1) # 1=Beginner, 2=Inter, 3=Adv
    github_repo_url = Column(String)
    
    required_skills = relationship("ProjectSkill", back_populates="project")


class ProjectSkill(Base):
    __tablename__ = "project_skills"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    skill_id = Column(Integer, ForeignKey("skills.id"))

    project = relationship("Project", back_populates="required_skills")
    skill = relationship("Skill")

