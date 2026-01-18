import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

export default function LearningHub() {
    const [resources, setResources] = useState([]);

    useEffect(() => {
        api.get('/skills/resources')
            .then(res => setResources(res.data))
            .catch(err => console.error(err));
    }, []);

    return (
        <div className="container animate-fade-in">
            <h2 className="heading">Learning Hub</h2>
            <p className="text-secondary" style={{ marginBottom: '2rem' }}>
                Curated courses, certifications, and projects from top providers like Udemy, Coursera, and EdX.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1.5rem' }}>
                {resources.map((res, i) => (
                    <div key={i} className="card" style={{ display: 'flex', flexDirection: 'column' }}>
                        <div style={{
                            height: '140px',
                            background: 'linear-gradient(45deg, var(--bg-primary), var(--bg-secondary))',
                            borderRadius: '6px',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            marginBottom: '1rem', border: '1px solid rgba(255,255,255,0.05)'
                        }}>
                            <span style={{ fontSize: '3rem' }}>
                                {res.type === 'Course' ? '🎓' : res.type === 'Project' ? '🛠️' : '📜'}
                            </span>
                        </div>

                        <h4 style={{ fontWeight: '600', marginBottom: '0.5rem', flex: 1 }}>{res.title}</h4>

                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', color: '#94a3b8', marginBottom: '1rem' }}>
                            <span>{res.provider}</span>
                            <span>Level {res.difficulty_level}/5</span>
                        </div>

                        <a
                            href={res.link}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn btn-secondary"
                            style={{
                                width: '100%',
                                textAlign: 'center',
                                display: 'block',
                                textDecoration: 'none'
                            }}
                        >
                            Start Learning ↗
                        </a>
                    </div>
                ))}
            </div>
        </div>
    );
}
