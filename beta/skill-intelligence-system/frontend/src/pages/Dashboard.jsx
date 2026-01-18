import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { userService, roleService } from '../services/api';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

import { useAuth } from '../context/AuthContext';

export default function Dashboard() {
    const { user } = useAuth();
    const [userSkills, setUserSkills] = useState([]);
    const [recs, setRecs] = useState([]);
    const [allRoles, setAllRoles] = useState([]);
    const [targetRoleId, setTargetRoleId] = useState('');
    const [loading, setLoading] = useState(true);

    const USER_ID = user?.id; // Dynamic ID

    useEffect(() => {
        if (!USER_ID) return;
        const fetchData = async () => {
            try {
                const [uRes, rRes, rolesRes] = await Promise.all([
                    userService.get(USER_ID),
                    roleService.recommend(USER_ID),
                    roleService.list()
                ]);
                setUserSkills(uRes.data.skills);
                setRecs(rRes.data.slice(0, 3)); // Top 3
                setAllRoles(rolesRes.data);

                if (uRes.data.target_role_id) {
                    setTargetRoleId(uRes.data.target_role_id);
                }
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    const handleSetGoal = async (e) => {
        const newTarget = e.target.value;
        setTargetRoleId(newTarget);
        try {
            await userService.update(USER_ID, { target_role_id: parseInt(newTarget) });
        } catch (err) {
            console.error("Failed to set goal", err);
        }
    };

    // Calculate Goal Progress
    const getGoalProgress = () => {
        if (!targetRoleId) return null;
        const targetRole = allRoles.find(r => r.id === parseInt(targetRoleId));
        if (!targetRole) return null;

        const totalReqs = targetRole.required_skills.length;
        let completed = 0;
        const missing = [];

        targetRole.required_skills.forEach(req => {
            const userSkill = userSkills.find(us => us.skill.id === req.skill_id);
            if (userSkill && userSkill.proficiency_level >= req.required_level) {
                completed++;
            } else {
                missing.push({
                    name: req.skill.name,
                    reqLevel: req.required_level,
                    myLevel: userSkill ? userSkill.proficiency_level : 0
                });
            }
        });

        return { targetRole, totalReqs, completed, missing, percent: totalReqs === 0 ? 0 : Math.round((completed / totalReqs) * 100) };
    };

    const goalData = getGoalProgress();

    // Chart Data
    const chartData = {
        labels: userSkills.map(s => s.skill.name),
        datasets: [
            {
                label: 'Proficiency Level',
                data: userSkills.map(s => s.proficiency_level),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.6)',
                    'rgba(54, 162, 235, 0.6)',
                    'rgba(255, 206, 86, 0.6)',
                    'rgba(75, 192, 192, 0.6)',
                    'rgba(153, 102, 255, 0.6)',
                    'rgba(255, 159, 64, 0.6)',
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)',
                    'rgba(255, 159, 64, 1)',
                ],
                borderWidth: 1,
            },
        ],
    };

    return (
        <div className="container animate-fade-in">
            <header style={{ marginBottom: '3rem', marginTop: '2rem' }}>
                <h1 className="heading" style={{ fontSize: '2.5rem' }}>Dashboard</h1>
                <p className="text-secondary" style={{ fontSize: '1.2rem', maxWidth: '600px' }}>
                    Overview of your skills, career matches, and active learning goals.
                </p>
                <div style={{ marginTop: '2rem', display: 'flex', gap: '1rem' }}>
                    <Link to="/profile" className="btn btn-secondary">Update Profile</Link>
                    <Link to="/roles" className="btn btn-primary">Find Matches</Link>
                </div>
            </header>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '2rem' }}>

                {/* 1. Skill Coverage Chart */}
                <div className="card">
                    <h3 className="heading">Skill Coverage</h3>
                    <p className="text-secondary" style={{ marginBottom: '1rem' }}>Proficiency distribution.</p>
                    {userSkills.length > 0 ? (
                        <div style={{ height: '240px', display: 'flex', justifyContent: 'center' }}>
                            <Doughnut
                                data={chartData}
                                options={{
                                    maintainAspectRatio: false,
                                    plugins: {
                                        legend: {
                                            display: false // Hide the names above the graph
                                        }
                                    }
                                }}
                            />
                        </div>
                    ) : (
                        <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
                            No skills added yet. Go to Profile to add some!
                        </div>
                    )}
                </div>

                {/* 2. Recent Recommendations */}
                <div className="card">
                    <h3 className="heading">Top Recommendations</h3>
                    <p className="text-secondary" style={{ marginBottom: '1rem' }}>Based on your gaps.</p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {recs.map(rec => (
                            <Link to="/roles" key={rec.role_id} style={{ textDecoration: 'none' }}>
                                <div style={{
                                    padding: '1rem',
                                    background: 'rgba(255,255,255,0.05)',
                                    borderRadius: '6px',
                                    borderLeft: `3px solid ${rec.readiness_score > 0.6 ? 'var(--success)' : 'var(--warning)'}`
                                }}>
                                    <div style={{ color: 'white', fontWeight: 'bold' }}>{rec.role_title}</div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                                        <span className="text-secondary">{rec.domain}</span>
                                        <span style={{ color: 'var(--brand-primary)' }}>{(rec.readiness_score * 100).toFixed(0)}% Ready</span>
                                    </div>
                                </div>
                            </Link>
                        ))}
                        {recs.length === 0 && !loading && <span className="text-secondary">No recommendations found. add skills first!</span>}
                    </div>
                </div>

                {/* 3. My Goal Widget */}
                <div className="card">
                    <h3 className="heading">My Career Goal</h3>
                    <p className="text-secondary" style={{ marginBottom: '1rem' }}>Set a dream job and track readiness.</p>

                    <div style={{ marginBottom: '1.5rem' }}>
                        <select
                            value={targetRoleId}
                            onChange={handleSetGoal}
                            style={{
                                width: '100%', padding: '0.75rem', borderRadius: '4px',
                                border: '1px solid #334155', background: '#0f172a', color: 'white'
                            }}
                        >
                            <option value="">-- Select Dream Job --</option>
                            {allRoles.map(r => (
                                <option key={r.id} value={r.id}>{r.title}</option>
                            ))}
                        </select>
                    </div>

                    {goalData ? (
                        <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                <span style={{ fontWeight: 'bold', color: 'var(--brand-primary)' }}>{goalData.targetRole.title}</span>
                                <span style={{ color: goalData.percent === 100 ? 'var(--success)' : 'white' }}>{goalData.percent}% Ready</span>
                            </div>

                            {/* Progress Bar */}
                            <div style={{ height: '8px', background: '#334155', borderRadius: '4px', overflow: 'hidden', marginBottom: '1.5rem' }}>
                                <div style={{
                                    width: `${goalData.percent}%`,
                                    height: '100%',
                                    background: goalData.percent === 100 ? 'var(--success)' : 'var(--brand-primary)',
                                    transition: 'width 0.5s ease'
                                }}></div>
                            </div>

                            {goalData.missing.length > 0 ? (
                                <div>
                                    <h4 style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '0.5rem' }}>Missing Skills:</h4>
                                    <ul style={{ listStyle: 'none', padding: 0 }}>
                                        {goalData.missing.slice(0, 3).map((m, i) => (
                                            <li key={i} style={{
                                                marginBottom: '0.5rem', fontSize: '0.85rem',
                                                display: 'flex', justifyContent: 'space-between',
                                                borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '4px'
                                            }}>
                                                <span>{m.name}</span>
                                                <span style={{ color: 'var(--error)' }}>
                                                    Lvl {m.myLevel}/{m.reqLevel}
                                                </span>
                                            </li>
                                        ))}
                                        {goalData.missing.length > 3 && (
                                            <li style={{ fontSize: '0.8rem', color: '#64748b', textAlign: 'center' }}>
                                                + {goalData.missing.length - 3} more...
                                            </li>
                                        )}
                                    </ul>
                                    <div style={{ textAlign: 'center', marginTop: '1rem' }}>
                                        <Link to="/roles" style={{ fontSize: '0.85rem', color: 'var(--brand-secondary)' }}>View Full Gap Analysis &rarr;</Link>
                                    </div>
                                </div>
                            ) : (
                                <div style={{ textAlign: 'center', color: 'var(--success)', padding: '1rem' }}>
                                    🎉 You are fully qualified for this role!
                                </div>
                            )}
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b', fontStyle: 'italic' }}>
                            Select a role above to see your path.
                        </div>
                    )}
                </div>

            </div>
        </div>
    );
}
