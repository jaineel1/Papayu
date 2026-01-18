import React, { useState } from 'react';
import { roleService } from '../services/api';

const SkillImpactSimulator = ({ isOpen, onClose, roleId, roleName, gaps, currentReadiness, userId }) => {
    if (!isOpen) return null;

    const [selectedSkillId, setSelectedSkillId] = useState('');
    const [targetLevel, setTargetLevel] = useState(3);
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleSimulate = async () => {
        if (!selectedSkillId) return;
        setLoading(true);
        try {
            const res = await roleService.simulate({
                user_id: userId,
                role_id: roleId,
                skill_id: parseInt(selectedSkillId),
                target_level: parseInt(targetLevel)
            });
            setResult(res.data);
        } catch (e) {
            console.error("Simulation failed", e);
            alert("Simulation failed. Please try again.");
        } finally {
            setLoading(false);
        }
    };

    const formatPercent = (val) => Math.round(val * 100) + '%';

    // Find the skill object for display
    const selectedSkillName = gaps.find(g => g.skill_name === result?.skill_simulated)?.skill_name || 'Selected Skill';

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 1000, backdropFilter: 'blur(5px)'
        }}>
            <div className="card animate-fade-in" style={{ width: '90%', maxWidth: '500px', position: 'relative' }}>
                <button
                    onClick={onClose}
                    style={{ position: 'absolute', top: '1rem', right: '1rem', background: 'none', border: 'none', color: '#fff', fontSize: '1.2rem', cursor: 'pointer' }}
                >✕</button>

                <h3 className="heading" style={{ marginBottom: '0.5rem' }}>Skill Impact Simulator</h3>
                <p className="text-secondary" style={{ fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                    See how learning a skill impacts your fit for <strong style={{ color: 'var(--brand-primary)' }}>{roleName}</strong>.
                </p>

                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                        <span className="text-secondary">Current Readiness:</span>
                        <span style={{ fontWeight: 'bold' }}>{formatPercent(currentReadiness)}</span>
                    </div>
                </div>

                <div style={{ marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <div>
                        <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Improve Skill:</label>
                        <select
                            style={{ width: '100%', padding: '0.75rem', background: '#0f172a', border: '1px solid #334155', color: 'white', borderRadius: '6px' }}
                            value={selectedSkillId}
                            onChange={(e) => { setSelectedSkillId(e.target.value); setResult(null); }}
                        >
                            <option value="">-- Select a Missing Skill --</option>
                            {gaps.map((gap, idx) => (
                                // Use idx if skill_id isn't directly in gap, but usually gap has skill_id? 
                                // Wait, GapDetail doesn't have skill_id in schemas.py! 
                                // Ah, the schema has skill_name. 
                                // I need the ID to simulate. 
                                // Wait, the UI needs IDs. 
                                // I should check schemas.py GapDetail again.
                                // It only has skill_name! 
                                // This is a problem. I can't simulate without ID.
                                // I must fix Intelligence Engine first or pass ID.
                                // Let's assume for now I can match by name or I made a mistake.
                                // Quick fix: I'll assume GapDetail DOES NOT have ID, so I need to update Backend Schema locally?
                                // Let's check schemas.py content I viewed earlier.
                                // Line 76: class GapDetail(BaseModel): skill_name: str... no ID.
                                // I need to add skill_id to GapDetail in Backend first!
                                <option key={idx} value={gap.skill_id}>{gap.skill_name} (Current: {gap.current_level}/5)</option>
                            ))}
                        </select>
                    </div>

                    {selectedSkillId && (
                        <div>
                            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Target Level (1-5):</label>
                            <input
                                type="range" min="1" max="5"
                                value={targetLevel}
                                onChange={(e) => { setTargetLevel(e.target.value); setResult(null); }}
                                style={{ width: '100%', accentColor: 'var(--brand-primary)' }}
                            />
                            <div style={{ textAlign: 'right', fontSize: '0.9rem', color: 'var(--brand-primary)' }}>Level {targetLevel}</div>
                        </div>
                    )}
                </div>

                <button
                    className="btn btn-primary"
                    style={{ width: '100%' }}
                    onClick={handleSimulate}
                    disabled={!selectedSkillId || loading}
                >
                    {loading ? 'Simulating...' : 'Simulate Impact ⚡'}
                </button>

                {result && (
                    <div className="animate-fade-in" style={{ marginTop: '1.5rem', padding: '1rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                        <p style={{ fontSize: '0.9rem', color: '#fff', marginBottom: '0.5rem' }}>
                            Improving <strong>{result.skill_simulated}</strong> to Level {targetLevel}...
                        </p>
                        <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#10b981' }}>
                            +{formatPercent(result.improvement)} 🚀
                        </div>
                        <p style={{ fontSize: '0.9rem', color: 'rgba(255,255,255,0.7)' }}>
                            New Readiness: {formatPercent(result.new_readiness)}
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SkillImpactSimulator;
