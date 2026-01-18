import React, { useEffect, useState } from 'react';
import { roleService } from '../services/api';
import { Chart as ChartJS, RadialLinearScale, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { useAuth } from '../context/AuthContext';
import SkillImpactSimulator from '../components/SkillImpactSimulator';

ChartJS.register(RadialLinearScale, ArcElement, Tooltip, Legend);

export default function RoleExplorer() {
    const { user } = useAuth();
    const [recommendations, setRecommendations] = useState([]);
    const [expandedRole, setExpandedRole] = useState(null);
    const [simulationRole, setSimulationRole] = useState(null);
    const USER_ID = user?.id;

    useEffect(() => {
        if (!USER_ID) return;
        const fetchData = async () => {
            // Only load recommendations if USER_ID is available
            loadRecs();
        }
        fetchData(); // Call the async function
    }, [USER_ID]); // Re-run effect if USER_ID changes

    const loadRecs = async () => {
        try {
            const res = await roleService.recommend(USER_ID);
            setRecommendations(res.data);
        } catch (e) {
            console.error(e);
        }
    };

    const toggleExpand = (roleId) => {
        setExpandedRole(expandedRole === roleId ? null : roleId);
    };

    return (
        <div className="container animate-fade-in">
            <h2 className="heading">Job Role Intelligence</h2>
            <p className="text-secondary" style={{ marginBottom: '2rem' }}>
                Ranking jobs based on your current skill profile match.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {recommendations.map(rec => {
                    const isExpanded = expandedRole === rec.role_id;
                    const scoreColor = rec.readiness_score > 0.7 ? 'var(--success)' : rec.readiness_score > 0.4 ? 'var(--warning)' : 'var(--error)';

                    return (
                        <div key={rec.role_id} className="card" style={{ borderLeft: `4px solid ${scoreColor} ` }}>
                            <div
                                style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                                onClick={() => toggleExpand(rec.role_id)}
                            >
                                <div>
                                    <h3 style={{ fontSize: '1.25rem', fontWeight: '600', color: 'white' }}>{rec.role_title}</h3>
                                    <span className="text-sm text-secondary">{rec.domain}</span>
                                </div>
                                <div style={{ textAlign: 'right' }}>
                                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: scoreColor }}>
                                        {(rec.readiness_score * 100).toFixed(0)}% Ready
                                    </div>
                                    <div className="text-sm text-secondary">{rec.missing_skill_count} Missing Skills</div>
                                </div>
                            </div>

                            {isExpanded && (
                                <div style={{ marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                                    <h4 className="heading" style={{ fontSize: '1rem' }}>Gap Analysis</h4>

                                    <div style={{ display: 'grid', gap: '1rem', marginTop: '1rem' }}>
                                        {rec.gaps.map((gap, idx) => (
                                            <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '4px' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                                                    <span style={{ fontWeight: '500', color: 'var(--brand-secondary)' }}>{gap.skill_name}</span>
                                                    <span className="text-sm text-secondary">Gap Level: {gap.gap}</span>
                                                </div>

                                                <div style={{ height: '6px', background: '#334155', borderRadius: '3px', overflow: 'hidden' }}>
                                                    {/* User level bar */}
                                                    <div style={{
                                                        width: `${(gap.current_level / 5) * 100}% `,
                                                        height: '100%',
                                                        background: 'var(--brand-primary)',
                                                        float: 'left'
                                                    }}></div>
                                                    {/* Required level marker logic is complex in CSS, simplifying */}
                                                </div>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginTop: '4px', color: '#64748b' }}>
                                                    <span>Level {gap.current_level} (You)</span>
                                                    <span>Target: Level {gap.required_level}</span>
                                                </div>

                                                {gap.recommended_resources.length > 0 && (
                                                    <div style={{ marginTop: '0.75rem' }}>
                                                        <p className="text-sm" style={{ color: '#94a3b8' }}>Recommended Learning:</p>
                                                        {gap.recommended_resources.map((res, i) => (
                                                            <a
                                                                href={res.link || '#'}
                                                                key={i}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                style={{
                                                                    display: 'block',
                                                                    fontSize: '0.9rem',
                                                                    marginTop: '4px',
                                                                    color: res.link ? 'var(--brand-secondary)' : '#64748b',
                                                                    textDecoration: 'none',
                                                                    cursor: res.link ? 'pointer' : 'default'
                                                                }}
                                                            >
                                                                📚 {res.title} ({res.provider}) ↗
                                                            </a>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>

                                    {rec.gaps.length === 0 && (
                                        <div style={{ color: 'var(--success)', padding: '1rem' }}>
                                            ✨ You are a perfect match for this role!
                                        </div>
                                    )}

                                    {/* Simulation Button */}
                                    <button
                                        className="btn"
                                        style={{
                                            marginTop: '1.5rem',
                                            width: '100%',
                                            background: 'rgba(255, 255, 255, 0.05)',
                                            color: '#fff',
                                            border: '1px solid rgba(255,255,255,0.2)'
                                        }}
                                        onClick={(e) => { e.stopPropagation(); setSimulationRole(rec); }}
                                    >
                                        ⚡ Simulate Skill Impact
                                    </button>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>

            {/* Simulator Modal */}
            {simulationRole && (
                <SkillImpactSimulator
                    isOpen={!!simulationRole}
                    onClose={() => setSimulationRole(null)}
                    roleId={simulationRole.role_id}
                    roleName={simulationRole.role_title}
                    gaps={simulationRole.gaps}
                    currentReadiness={simulationRole.readiness_score}
                    userId={USER_ID}
                />
            )}
        </div>
    );
}
