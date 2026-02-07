import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
    FileSearch,
    AlertTriangle,
    CheckCircle,
    Clock,
    TrendingUp,
    Activity,
    Shield,
    Upload
} from 'lucide-react'
import {
    Chart as ChartJS,
    ArcElement,
    Tooltip,
    Legend,
    CategoryScale,
    LinearScale,
    BarElement,
    LineElement,
    PointElement
} from 'chart.js'
import { Doughnut, Bar } from 'react-chartjs-2'
import { reportsAPI, analysisAPI } from '../../services/api'
import './Dashboard.css'

// Register ChartJS components
ChartJS.register(
    ArcElement,
    Tooltip,
    Legend,
    CategoryScale,
    LinearScale,
    BarElement,
    LineElement,
    PointElement
)

function Dashboard() {
    const [stats, setStats] = useState(null)
    const [recentAnalyses, setRecentAnalyses] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        loadDashboardData()
    }, [])

    const loadDashboardData = async () => {
        try {
            setLoading(true)

            // Try to fetch real data, fall back to mock data
            try {
                const [statsData, analysesData] = await Promise.all([
                    reportsAPI.getStatistics(30),
                    analysisAPI.listAnalyses({ limit: 5 })
                ])
                setStats(statsData)
                setRecentAnalyses(analysesData.tasks || [])
            } catch (error) {
                // Use mock data for demo
                setStats(getMockStats())
                setRecentAnalyses(getMockAnalyses())
            }
        } finally {
            setLoading(false)
        }
    }

    const getMockStats = () => ({
        total_analyses: 156,
        completed: 142,
        pending: 8,
        failed: 6,
        average_threat_score: 42,
        threat_distribution: {
            safe: 45,
            low: 38,
            medium: 32,
            high: 18,
            critical: 9
        },
        daily_submissions: {
            '2026-02-01': 12,
            '2026-02-02': 18,
            '2026-02-03': 15,
            '2026-02-04': 22,
            '2026-02-05': 19,
            '2026-02-06': 25,
            '2026-02-07': 14
        }
    })

    const getMockAnalyses = () => [
        { task_id: 'abc123', filename: 'suspicious.exe', status: 'completed', threat_level: 'high', submitted_at: '2026-02-07T10:30:00' },
        { task_id: 'def456', filename: 'invoice.pdf', status: 'completed', threat_level: 'safe', submitted_at: '2026-02-07T09:15:00' },
        { task_id: 'ghi789', filename: 'update.dll', status: 'running', threat_level: 'unknown', submitted_at: '2026-02-07T08:45:00' },
        { task_id: 'jkl012', filename: 'document.docm', status: 'completed', threat_level: 'medium', submitted_at: '2026-02-06T16:20:00' },
        { task_id: 'mno345', filename: 'setup.msi', status: 'completed', threat_level: 'critical', submitted_at: '2026-02-06T14:10:00' },
    ]

    const threatChartData = {
        labels: ['Safe', 'Low', 'Medium', 'High', 'Critical'],
        datasets: [{
            data: stats ? [
                stats.threat_distribution.safe || 0,
                stats.threat_distribution.low || 0,
                stats.threat_distribution.medium || 0,
                stats.threat_distribution.high || 0,
                stats.threat_distribution.critical || 0
            ] : [],
            backgroundColor: [
                '#22c55e',
                '#84cc16',
                '#f59e0b',
                '#f97316',
                '#ef4444'
            ],
            borderWidth: 0
        }]
    }

    const activityChartData = {
        labels: stats ? Object.keys(stats.daily_submissions).map(d => d.split('-')[2]) : [],
        datasets: [{
            label: 'Analyses',
            data: stats ? Object.values(stats.daily_submissions) : [],
            backgroundColor: 'rgba(59, 130, 246, 0.5)',
            borderColor: '#3b82f6',
            borderWidth: 2,
            borderRadius: 4
        }]
    }

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: '#94a3b8'
                }
            },
            x: {
                grid: {
                    display: false
                },
                ticks: {
                    color: '#94a3b8'
                }
            }
        }
    }

    if (loading) {
        return (
            <div className="loading">
                <div className="spinner"></div>
            </div>
        )
    }

    return (
        <div className="dashboard animate-fade-in">
            <div className="dashboard-header">
                <div>
                    <h1>Dashboard</h1>
                    <p className="text-muted">Malware Analysis Overview</p>
                </div>
                <Link to="/upload" className="btn btn-primary">
                    <Upload size={18} />
                    New Analysis
                </Link>
            </div>

            {/* Stats Grid */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-label">
                        <FileSearch size={18} />
                        Total Analyses
                    </div>
                    <div className="stat-value">{stats?.total_analyses || 0}</div>
                </div>

                <div className="stat-card">
                    <div className="stat-label">
                        <CheckCircle size={18} style={{ color: 'var(--color-success)' }} />
                        Completed
                    </div>
                    <div className="stat-value">{stats?.completed || 0}</div>
                </div>

                <div className="stat-card">
                    <div className="stat-label">
                        <Clock size={18} style={{ color: 'var(--color-warning)' }} />
                        Pending
                    </div>
                    <div className="stat-value">{stats?.pending || 0}</div>
                </div>

                <div className="stat-card">
                    <div className="stat-label">
                        <AlertTriangle size={18} style={{ color: 'var(--color-danger)' }} />
                        Avg Threat Score
                    </div>
                    <div className="stat-value">{Math.round(stats?.average_threat_score || 0)}</div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="charts-row">
                <div className="card chart-card">
                    <div className="card-header">
                        <h3 className="card-title">
                            <Shield size={20} />
                            Threat Distribution
                        </h3>
                    </div>
                    <div className="chart-container doughnut-chart">
                        <Doughnut
                            data={threatChartData}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                cutout: '65%',
                                plugins: {
                                    legend: {
                                        position: 'right',
                                        labels: {
                                            color: '#94a3b8',
                                            padding: 15,
                                            usePointStyle: true
                                        }
                                    }
                                }
                            }}
                        />
                    </div>
                </div>

                <div className="card chart-card">
                    <div className="card-header">
                        <h3 className="card-title">
                            <TrendingUp size={20} />
                            Daily Activity
                        </h3>
                    </div>
                    <div className="chart-container bar-chart">
                        <Bar data={activityChartData} options={chartOptions} />
                    </div>
                </div>
            </div>

            {/* Recent Analyses */}
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">
                        <Activity size={20} />
                        Recent Analyses
                    </h3>
                    <Link to="/analyses" className="btn btn-secondary">
                        View All
                    </Link>
                </div>
                <table className="table">
                    <thead>
                        <tr>
                            <th>File Name</th>
                            <th>Status</th>
                            <th>Threat Level</th>
                            <th>Submitted</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {recentAnalyses.map((analysis) => (
                            <tr key={analysis.task_id}>
                                <td>
                                    <div className="mono truncate" style={{ maxWidth: 200 }}>
                                        {analysis.filename}
                                    </div>
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
                                    <Link
                                        to={`/analysis/${analysis.task_id}`}
                                        className="btn btn-secondary"
                                        style={{ padding: '0.25rem 0.75rem' }}
                                    >
                                        View
                                    </Link>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}

export default Dashboard
