import React, { useEffect, useState } from 'react';
import { api, userService } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function UserProfile() {
    const { user } = useAuth(); // Get real logged in user
    const [backendUser, setBackendUser] = useState(null);
    const [allSkills, setAllSkills] = useState([]);
    const [newSkillId, setNewSkillId] = useState('');
    const [newSkillLevel, setNewSkillLevel] = useState(1);

    // For this Hybrid Firebase/SQLite version, we keep mapping to Backend User ID 1
    // to ensure the intelligence engine has data to work with.
    const USER_ID = user?.id;

    useEffect(() => {
        if (USER_ID) {
            loadUser();
        }
        loadSkills();
    }, [USER_ID]);

    const loadUser = async () => {
        if (!USER_ID) return;
        try {
            const res = await userService.get(USER_ID);
            setBackendUser(res.data);
        } catch (e) { console.error("Err loading user", e); }
    };

    const loadSkills = async () => {
        try {
            const res = await api.get('/skills/');
            setAllSkills(res.data);
        } catch (e) { console.error("Err loading skills", e); }
    };

    const handleAddSkill = async (e) => {
        e.preventDefault();
        if (!newSkillId) return;
        try {
            await userService.addSkill(USER_ID, parseInt(newSkillId), parseInt(newSkillLevel));
            loadUser(); // Refresh
            alert("Skill Added!");
        } catch (e) {
            alert("Failed to add skill");
        }
    };

    const handleRemoveSkill = async (skillId) => {
        if (!window.confirm("Are you sure you want to remove this skill?")) return;
        try {
            await userService.removeSkill(USER_ID, skillId);
            loadUser(); // Refresh
        } catch (e) {
            alert("Failed to remove skill");
            console.error(e);
        }
    };

    const [isEditing, setIsEditing] = useState(false);
    const [editRole, setEditRole] = useState('');

    const startEditing = () => {
        setEditRole(backendUser.current_role_title || '');
        setIsEditing(true);
    };

    const handleUpdateRole = async () => {
        try {
            await userService.update(USER_ID, { current_role_title: editRole });
            setIsEditing(false);
            loadUser();
        } catch (e) {
            alert("Failed to update role");
        }
    };

    if (!backendUser) {
        return (
            <div className="container" style={{ textAlign: 'center', marginTop: '4rem' }}>
                <h2 className="heading">Loading Profile...</h2>
                <p className="text-secondary">
                    {USER_ID ? "Fetching your data from the backend..." : "Identifying user session..."}
                </p>
                {!USER_ID && (
                    <p style={{ color: 'var(--warning)', marginTop: '1rem', fontSize: '0.9rem' }}>
                        (Note: If this persists, try refreshing or logging out and back in.)
                    </p>
                )}
            </div>
        );
    }

    return (
        <div className="container animate-fade-in">
            <h2 className="heading">My Profile</h2>

            <div className="card" style={{ marginBottom: '2rem' }}>
                {/* Use Auth Name if available, else backend name */}
                <h3 className="heading" style={{ fontSize: '1.5rem' }}>{user?.name || backendUser.full_name}</h3>
                <p className="text-secondary">{user?.email || backendUser.email}</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.5rem' }}>
                    {isEditing ? (
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <input
                                type="text"
                                value={editRole}
                                onChange={e => setEditRole(e.target.value)}
                                style={{ padding: '0.25rem 0.5rem', borderRadius: '4px', border: '1px solid #334155', background: '#0f172a', color: 'white' }}
                            />
                            <button onClick={handleUpdateRole} className="btn btn-primary" style={{ padding: '0.25rem 0.75rem', fontSize: '0.9rem' }}>Save</button>
                            <button onClick={() => setIsEditing(false)} className="btn btn-secondary" style={{ padding: '0.25rem 0.75rem', fontSize: '0.9rem' }}>Cancel</button>
                        </div>
                    ) : (
                        <>
                            <p style={{ color: 'var(--brand-primary)', margin: 0 }}>{backendUser.current_role_title || 'N/A'}</p>
                            <button onClick={startEditing} style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '0.9rem', textDecoration: 'underline' }}>
                                Edit Role
                            </button>
                        </>
                    )}
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                <div className="card">
                    <h3 className="heading">Current Skills</h3>
                    {backendUser.skills.length === 0 ? <p className="text-secondary">No skills added yet.</p> : (
                        <ul style={{ listStyle: 'none' }}>
                            {backendUser.skills.map(us => (
                                <li key={us.id} style={{
                                    padding: '0.75rem',
                                    borderBottom: '1px solid rgba(255,255,255,0.05)',
                                    display: 'flex', justifyContent: 'space-between'
                                }}>
                                    <span>{us.skill.name}</span>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                        <span style={{
                                            background: 'rgba(255,255,255,0.1)',
                                            padding: '2px 8px', borderRadius: '4px', fontSize: '0.8rem'
                                        }}>
                                            Level {us.proficiency_level}/5
                                        </span>
                                        <button
                                            onClick={() => handleRemoveSkill(us.skill.id)}
                                            style={{
                                                background: 'transparent', border: 'none', color: 'var(--error)',
                                                cursor: 'pointer', fontSize: '1.2rem', padding: 0
                                            }}
                                            title="Remove Skill"
                                        >
                                            ×
                                        </button>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>

                <div className="card">
                    <h3 className="heading">Add New Skill</h3>
                    <form onSubmit={handleAddSkill} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        <div>
                            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Select Skill</label>
                            <select
                                style={{ width: '100%', padding: '0.5rem' }}
                                value={newSkillId}
                                onChange={e => setNewSkillId(e.target.value)}
                            >
                                <option value="">-- Choose --</option>
                                {allSkills.map(s => (
                                    <option key={s.id} value={s.id}>{s.name} ({s.category})</option>
                                ))}
                            </select>
                        </div>

                        <div>
                            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Proficiency (1-5)</label>
                            <input
                                type="number" min="1" max="5"
                                style={{ width: '100%', padding: '0.5rem' }}
                                value={newSkillLevel}
                                onChange={e => setNewSkillLevel(e.target.value)}
                            />
                        </div>

                        <button type="submit" className="btn btn-primary">Add Skill</button>
                    </form>
                </div>
            </div>
        </div>
    );
}
