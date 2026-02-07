import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { FileSearch, Trash2, RefreshCw } from 'lucide-react'
import { analysisAPI } from '../../services/api'

function AnalysisList() {
    const [analyses, setAnalyses] = useState([])
    const [loading, setLoading] = useState(true)
    const [filter, setFilter] = useState('')

    useEffect(() => {
        loadAnalyses()
    }, [])

    const loadAnalyses = async () => {
        try {
            setLoading(true)
            try {
                const data = await analysisAPI.listAnalyses({ limit: 100 })
                setAnalyses(data.tasks || [])
            } catch {
                // Mock data for demo
                setAnalyses([
                    { task_id: 'abc123', filename: 'suspicious.exe', status: 'completed', threat_level: 'high', submitted_at: '2026-02-07T10:30:00' },
                    { task_id: 'def456', filename: 'invoice.pdf', status: 'completed', threat_level: 'safe', submitted_at: '2026-02-07T09:15:00' },
                    { task_id: 'ghi789', filename: 'update.dll', status: 'running', threat_level: 'unknown', submitted_at: '2026-02-07T08:45:00' },
                    { task_id: 'jkl012', filename: 'document.docm', status: 'completed', threat_level: 'medium', submitted_at: '2026-02-06T16:20:00' },
                    { task_id: 'mno345', filename: 'setup.msi', status: 'completed', threat_level: 'critical', submitted_at: '2026-02-06T14:10:00' },
                    { task_id: 'pqr678', filename: 'patch.exe', status: 'pending', threat_level: 'unknown', submitted_at: '2026-02-06T12:00:00' },
                    { task_id: 'stu901', filename: 'config.dll', status: 'completed', threat_level: 'low', submitted_at: '2026-02-05T18:30:00' },
                ])
            }
        } finally {
            setLoading(false)
        }
    }

    const handleDelete = async (taskId) => {
        if (!confirm('Are you sure you want to delete this analysis?')) return
        try {
            await analysisAPI.deleteAnalysis(taskId)
            setAnalyses(analyses.filter(a => a.task_id !== taskId))
        } catch (err) {
            console.error('Failed to delete:', err)
        }
    }

    const filteredAnalyses = analyses.filter(a =>
        a.filename.toLowerCase().includes(filter.toLowerCase()) ||
        a.task_id.toLowerCase().includes(filter.toLowerCase())
    )

    if (loading) {
        return <div className="loading"><div className="spinner"></div></div>
    }

    return (
        <div className="animate-fade-in">
            <div className="flex justify-between items-center mb-lg">
                <div>
                    <h1>Analyses</h1>
                    <p className="text-muted">All malware analysis tasks</p>
                </div>
                <button className="btn btn-secondary" onClick={loadAnalyses}>
                    <RefreshCw size={18} />
                    Refresh
                </button>
            </div>

            <div className="card">
                <div style={{ marginBottom: '1rem' }}>
                    <input
                        type="text"
                        placeholder="Search by filename or task ID..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        style={{ maxWidth: 400 }}
                    />
                </div>

                <table className="table">
                    <thead>
                        <tr>
                            <th>File Name</th>
                            <th>Task ID</th>
                            <th>Status</th>
                            <th>Threat Level</th>
                            <th>Submitted</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredAnalyses.map((analysis) => (
                            <tr key={analysis.task_id}>
                                <td>
                                    <div className="flex items-center gap-sm">
                                        <FileSearch size={16} style={{ color: 'var(--color-accent-blue)' }} />
                                        <span className="mono truncate" style={{ maxWidth: 200 }}>
                                            {analysis.filename}
                                        </span>
                                    </div>
                                </td>
                                <td className="mono text-muted" style={{ fontSize: '0.75rem' }}>
                                    {analysis.task_id}
                                </td>
                                <td>
                                    <span className={`badge badge-${analysis.status}`}>
                                        {analysis.status}
                                    </span>
                                </td>
                                <td>
                                    <span className={`threat-badge threat-${analysis.threat_level}`}>
                                        {analysis.threat_level}
                                    </span>
                                </td>
                                <td className="text-muted">
                                    {new Date(analysis.submitted_at).toLocaleString()}
                                </td>
                                <td>
                                    <div className="flex gap-sm">
                                        <Link
                                            to={`/analysis/${analysis.task_id}`}
                                            className="btn btn-secondary"
                                            style={{ padding: '0.25rem 0.75rem' }}
                                        >
                                            View
                                        </Link>
                                        <button
                                            className="btn btn-icon"
                                            onClick={() => handleDelete(analysis.task_id)}
                                            style={{ color: 'var(--color-danger)' }}
                                        >
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {filteredAnalyses.length === 0 && (
                    <div className="text-center text-muted" style={{ padding: '3rem' }}>
                        No analyses found
                    </div>
                )}
            </div>
        </div>
    )
}

export default AnalysisList
