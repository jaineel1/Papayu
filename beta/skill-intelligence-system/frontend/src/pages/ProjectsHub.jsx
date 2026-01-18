import React, { useEffect, useState } from 'react';
import { projectService } from '../services/api';
import ProjectCard from '../components/ProjectCard';
import { useAuth } from '../context/AuthContext';

export default function ProjectsHub() {
    const { user } = useAuth();
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filterDomain, setFilterDomain] = useState('All');

    useEffect(() => {
        if (user?.id) {
            loadProjects();
        }
    }, [user?.id]);

    const loadProjects = async () => {
        setLoading(true);
        try {
            const res = await projectService.recommend(user.id);
            setProjects(res.data);
        } catch (error) {
            console.error("Failed to load projects", error);
        } finally {
            setLoading(false);
        }
    };

    const domains = ['All', ...new Set(projects.map(p => p.domain))];
    const filteredProjects = filterDomain === 'All'
        ? projects
        : projects.filter(p => p.domain === filterDomain);

    return (
        <div className="container animate-fade-in">
            <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
                <h2 className="heading" style={{ fontSize: '2.5rem' }}>Projects Hub</h2>
                <p className="text-secondary" style={{ maxWidth: '600px', margin: '0 auto' }}>
                    Turn your skills into proof-of-work. Build real-world projects recommended based on your current skill set.
                </p>
            </div>

            {/* Filter */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
                {domains.map(d => (
                    <button
                        key={d}
                        onClick={() => setFilterDomain(d)}
                        className={`btn ${filterDomain === d ? 'btn-primary' : 'btn-outline'}`}
                        style={{ borderRadius: '20px', padding: '0.5rem 1.5rem' }}
                    >
                        {d}
                    </button>
                ))}
            </div>

            {loading ? (
                <div style={{ textAlign: 'center', padding: '4rem', color: '#94a3b8' }}>Loading recommendations...</div>
            ) : (
                <>
                    {projects.length === 0 ? (
                        <div style={{ textAlign: 'center', padding: '4rem', background: 'rgba(255,255,255,0.03)', borderRadius: '12px' }}>
                            <p>No matches found yet. Keep adding skills to your profile!</p>
                        </div>
                    ) : (
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '2rem' }}>
                            {filteredProjects.map(project => (
                                <ProjectCard key={project.id} project={project} />
                            ))}
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
