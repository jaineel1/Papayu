import React from 'react';

const ProjectCard = ({ project }) => {
    const { title, description, domain, difficulty_level, github_repo_url, required_skills, match_count, relevance_score } = project;

    // Difficulty logic
    let diffLabel = 'Beginner';
    let diffColor = 'var(--brand-secondary)';
    if (difficulty_level === 2) diffLabel = 'Intermediate';
    if (difficulty_level >= 3) { diffLabel = 'Advanced'; diffColor = 'var(--warning)'; }
    if (difficulty_level >= 4) { diffLabel = 'Expert'; diffColor = 'var(--error)'; }

    return (
        <div className="card animate-fade-in" style={{ display: 'flex', flexDirection: 'column', height: '100%', borderTop: `4px solid ${diffColor}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                <span className="badge" style={{ background: 'rgba(255,255,255,0.1)', color: '#ccc' }}>{domain}</span>
                <span style={{ fontSize: '0.8rem', color: diffColor, fontWeight: 'bold' }}>{diffLabel}</span>
            </div>

            <h3 style={{ fontSize: '1.2rem', marginBottom: '0.5rem', color: '#fff' }}>{title}</h3>
            <p className="text-secondary text-sm" style={{ flexGrow: 1, marginBottom: '1rem' }}>{description}</p>

            <div style={{ marginBottom: '1rem' }}>
                <p className="text-secondary text-xs" style={{ marginBottom: '0.25rem' }}>Required Skills:</p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                    {required_skills.slice(0, 4).map(s => (
                        <span key={s.skill_id} className="badge" style={{ fontSize: '0.7rem', background: '#1e293b' }}>
                            {s.skill_name}
                        </span>
                    ))}
                    {required_skills.length > 4 && <span className="badge" style={{ fontSize: '0.7rem' }}>+{required_skills.length - 4}</span>}
                </div>
            </div>

            <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--brand-primary)' }}>
                    {match_count} Skills Match
                </div>
                <a
                    href={github_repo_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-outline"
                    style={{ fontSize: '0.8rem', padding: '0.3rem 0.8rem' }}
                >
                    View on GitHub ↗
                </a>
            </div>
        </div>
    );
};

export default ProjectCard;
