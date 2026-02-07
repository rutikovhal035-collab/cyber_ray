import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
    FileSearch,
    Hash,
    Shield,
    Network,
    FolderOpen,
    Database,
    GitBranch,
    FileCode,
    Download,
    ArrowLeft,
    Clock,
    AlertTriangle,
    Activity
} from 'lucide-react'
import { analysisAPI, reportsAPI } from '../../services/api'
import './AnalysisReport.css'

function AnalysisReport() {
    const { taskId } = useParams()
    const [report, setReport] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [activeTab, setActiveTab] = useState('static')

    useEffect(() => {
        loadReport()
    }, [taskId])

    const loadReport = async () => {
        try {
            setLoading(true)
            try {
                const data = await analysisAPI.getReport(taskId)
                setReport(data)
            } catch (err) {
                // Use mock data for demo
                setReport(getMockReport())
            }
        } finally {
            setLoading(false)
        }
    }

    const getMockReport = () => ({
        task_id: taskId,
        filename: 'suspicious_sample.exe',
        status: 'completed',
        submitted_at: '2026-02-07T10:30:00',
        completed_at: '2026-02-07T10:35:00',
        threat_score: 78,
        threat_level: 'high',
        tags: ['trojan', 'persistence', 'c2-communication'],
        static_analysis: {
            hashes: {
                md5: 'd41d8cd98f00b204e9800998ecf8427e',
                sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                ssdeep: '3:Hn:Hn'
            },
            file_size: 245760,
            file_type: 'Windows Executable (PE)',
            pe_info: {
                is_pe: true,
                is_exe: true,
                architecture: 'x64',
                entry_point: '0x1000',
                subsystem: 'Windows GUI',
                compile_time: '2026-01-15T08:30:00',
                sections: [
                    { name: '.text', virtual_size: 16384, entropy: 6.2 },
                    { name: '.data', virtual_size: 8192, entropy: 5.1 },
                    { name: '.rdata', virtual_size: 4096, entropy: 4.8 },
                    { name: '.rsrc', virtual_size: 2048, entropy: 7.8 }
                ],
                imports: [
                    { dll: 'kernel32.dll', functions: ['CreateFileW', 'WriteFile', 'VirtualAlloc', 'CreateThread'] },
                    { dll: 'user32.dll', functions: ['MessageBoxW', 'GetAsyncKeyState'] },
                    { dll: 'ws2_32.dll', functions: ['socket', 'connect', 'send', 'recv'] }
                ],
                suspicious_imports: ['VirtualAlloc', 'CreateThread', 'GetAsyncKeyState', 'connect']
            },
            strings: ['http://malicious-c2.com', 'cmd.exe /c', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'],
            suspicious_strings: [
                'http://malicious-c2.com/beacon',
                'cmd.exe /c whoami',
                'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'powershell -enc',
                '\\AppData\\Local\\Temp\\payload.dll'
            ]
        },
        dynamic_analysis: {
            processes: [
                { pid: 1234, ppid: 1000, name: 'suspicious_sample.exe', path: 'C:\\Users\\Admin\\suspicious_sample.exe' },
                { pid: 1235, ppid: 1234, name: 'cmd.exe', path: 'C:\\Windows\\System32\\cmd.exe' },
                { pid: 1236, ppid: 1235, name: 'whoami.exe', path: 'C:\\Windows\\System32\\whoami.exe' }
            ],
            api_calls: [
                { api_name: 'CreateFileW', category: 'filesystem', arguments: { count: 15 } },
                { api_name: 'WriteFile', category: 'filesystem', arguments: { count: 8 } },
                { api_name: 'RegSetValueExW', category: 'registry', arguments: { count: 3 } },
                { api_name: 'InternetOpenW', category: 'network', arguments: { count: 2 } },
                { api_name: 'VirtualAllocEx', category: 'process', arguments: { count: 5 } }
            ],
            network_activity: [
                { protocol: 'TCP', dst_ip: '192.168.1.100', dst_port: 443, domain: 'malicious-c2.com' },
                { protocol: 'HTTP', dst_ip: '10.0.0.50', dst_port: 80, domain: 'update-server.net' }
            ],
            file_operations: [
                { operation: 'create', path: 'C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.dll' },
                { operation: 'modify', path: 'C:\\Windows\\System32\\drivers\\etc\\hosts' }
            ],
            registry_operations: [
                { operation: 'create', key: 'HKCU\\Software\\MalwareKey', value: 'config' },
                { operation: 'modify', key: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'malware' }
            ]
        }
    })

    const handleExport = async (format) => {
        try {
            const data = await reportsAPI.exportReport(taskId, format)

            if (format === 'json') {
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
                downloadBlob(blob, `report_${taskId}.json`)
            } else {
                downloadBlob(data, `report_${taskId}.html`)
            }
        } catch (err) {
            console.error('Export failed:', err)
        }
    }

    const downloadBlob = (blob, filename) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.click()
        URL.revokeObjectURL(url)
    }

    if (loading) {
        return (
            <div className="loading">
                <div className="spinner"></div>
            </div>
        )
    }

    if (error) {
        return (
            <div className="error-container">
                <AlertTriangle size={48} />
                <h2>Error Loading Report</h2>
                <p>{error}</p>
                <Link to="/analyses" className="btn btn-primary">Back to Analyses</Link>
            </div>
        )
    }

    const staticAnalysis = report?.static_analysis
    const dynamicAnalysis = report?.dynamic_analysis

    return (
        <div className="analysis-report animate-fade-in">
            {/* Header */}
            <div className="report-header">
                <Link to="/analyses" className="back-link">
                    <ArrowLeft size={20} />
                    Back to Analyses
                </Link>

                <div className="report-title-row">
                    <div>
                        <h1>{report?.filename}</h1>
                        <div className="report-meta">
                            <span className={`badge badge-${report?.status}`}>{report?.status}</span>
                            <span className="text-muted">
                                <Clock size={14} style={{ marginRight: 4 }} />
                                {new Date(report?.submitted_at).toLocaleString()}
                            </span>
                        </div>
                    </div>

                    <div className="report-actions">
                        <Link to={`/analysis/${taskId}/graph`} className="btn btn-secondary">
                            <GitBranch size={18} />
                            Behavior Graph
                        </Link>
                        <Link to={`/yara?task=${taskId}`} className="btn btn-secondary">
                            <FileCode size={18} />
                            Generate YARA
                        </Link>
                        <button className="btn btn-primary" onClick={() => handleExport('json')}>
                            <Download size={18} />
                            Export
                        </button>
                    </div>
                </div>

                {/* Threat Score */}
                <div className="threat-overview">
                    <div className="threat-score-card">
                        <div className="threat-score-value">{report?.threat_score}</div>
                        <div className="threat-score-label">Threat Score</div>
                    </div>
                    <div className={`threat-level-indicator threat-${report?.threat_level}`}>
                        <Shield size={24} />
                        <span>{report?.threat_level?.toUpperCase()}</span>
                    </div>
                    <div className="threat-tags">
                        {report?.tags?.map((tag, i) => (
                            <span key={i} className="tag">{tag}</span>
                        ))}
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="report-tabs">
                <button
                    className={`tab ${activeTab === 'static' ? 'active' : ''}`}
                    onClick={() => setActiveTab('static')}
                >
                    <FileSearch size={18} />
                    Static Analysis
                </button>
                <button
                    className={`tab ${activeTab === 'dynamic' ? 'active' : ''}`}
                    onClick={() => setActiveTab('dynamic')}
                >
                    <Activity size={18} />
                    Dynamic Analysis
                </button>
            </div>

            {/* Tab Content */}
            <div className="tab-content">
                {activeTab === 'static' && staticAnalysis && (
                    <div className="static-analysis">
                        {/* File Hashes */}
                        <div className="card">
                            <div className="card-header">
                                <h3 className="card-title"><Hash size={20} /> File Hashes</h3>
                            </div>
                            <table className="table hash-table">
                                <tbody>
                                    <tr>
                                        <td className="hash-label">MD5</td>
                                        <td className="hash-value mono">{staticAnalysis.hashes?.md5}</td>
                                    </tr>
                                    <tr>
                                        <td className="hash-label">SHA-1</td>
                                        <td className="hash-value mono">{staticAnalysis.hashes?.sha1}</td>
                                    </tr>
                                    <tr>
                                        <td className="hash-label">SHA-256</td>
                                        <td className="hash-value mono">{staticAnalysis.hashes?.sha256}</td>
                                    </tr>
                                    {staticAnalysis.hashes?.ssdeep && (
                                        <tr>
                                            <td className="hash-label">SSDeep</td>
                                            <td className="hash-value mono">{staticAnalysis.hashes.ssdeep}</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>

                        {/* PE Info */}
                        {staticAnalysis.pe_info && (
                            <div className="card">
                                <div className="card-header">
                                    <h3 className="card-title"><FileSearch size={20} /> PE Information</h3>
                                </div>
                                <div className="pe-info-grid">
                                    <div className="pe-item">
                                        <span className="pe-label">Type</span>
                                        <span className="pe-value">{staticAnalysis.pe_info.is_exe ? 'Executable' : 'DLL'}</span>
                                    </div>
                                    <div className="pe-item">
                                        <span className="pe-label">Architecture</span>
                                        <span className="pe-value">{staticAnalysis.pe_info.architecture}</span>
                                    </div>
                                    <div className="pe-item">
                                        <span className="pe-label">Subsystem</span>
                                        <span className="pe-value">{staticAnalysis.pe_info.subsystem}</span>
                                    </div>
                                    <div className="pe-item">
                                        <span className="pe-label">Entry Point</span>
                                        <span className="pe-value mono">{staticAnalysis.pe_info.entry_point}</span>
                                    </div>
                                </div>

                                {/* Sections */}
                                <h4 style={{ margin: '1.5rem 0 1rem' }}>Sections</h4>
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>Virtual Size</th>
                                            <th>Entropy</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {staticAnalysis.pe_info.sections?.map((sec, i) => (
                                            <tr key={i}>
                                                <td className="mono">{sec.name}</td>
                                                <td>{sec.virtual_size} bytes</td>
                                                <td>
                                                    <span className={sec.entropy > 7 ? 'text-danger' : ''}>
                                                        {sec.entropy?.toFixed(2)}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>

                                {/* Suspicious Imports */}
                                {staticAnalysis.pe_info.suspicious_imports?.length > 0 && (
                                    <>
                                        <h4 style={{ margin: '1.5rem 0 1rem', color: 'var(--color-warning)' }}>
                                            ⚠️ Suspicious Imports
                                        </h4>
                                        <div className="suspicious-list">
                                            {staticAnalysis.pe_info.suspicious_imports.map((imp, i) => (
                                                <span key={i} className="suspicious-item">{imp}</span>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                        )}

                        {/* Suspicious Strings */}
                        {staticAnalysis.suspicious_strings?.length > 0 && (
                            <div className="card">
                                <div className="card-header">
                                    <h3 className="card-title">
                                        <AlertTriangle size={20} style={{ color: 'var(--color-warning)' }} />
                                        Suspicious Strings
                                    </h3>
                                </div>
                                <div className="code-block">
                                    {staticAnalysis.suspicious_strings.map((str, i) => (
                                        <div key={i} className="string-item">{str}</div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {activeTab === 'dynamic' && dynamicAnalysis && (
                    <div className="dynamic-analysis">
                        {/* Process Tree */}
                        <div className="card">
                            <div className="card-header">
                                <h3 className="card-title"><GitBranch size={20} /> Process Tree</h3>
                            </div>
                            <div className="process-list">
                                {dynamicAnalysis.processes?.map((proc, i) => (
                                    <div key={i} className="process-item" style={{ marginLeft: i * 20 }}>
                                        <span className="process-icon">📦</span>
                                        <span className="process-name">{proc.name}</span>
                                        <span className="process-pid mono">PID: {proc.pid}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Network Activity */}
                        {dynamicAnalysis.network_activity?.length > 0 && (
                            <div className="card">
                                <div className="card-header">
                                    <h3 className="card-title"><Network size={20} /> Network Activity</h3>
                                </div>
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Protocol</th>
                                            <th>Destination</th>
                                            <th>Port</th>
                                            <th>Domain</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {dynamicAnalysis.network_activity.map((conn, i) => (
                                            <tr key={i}>
                                                <td><span className="badge badge-running">{conn.protocol}</span></td>
                                                <td className="mono">{conn.dst_ip}</td>
                                                <td>{conn.dst_port}</td>
                                                <td className="text-danger">{conn.domain || '-'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* File Operations */}
                        {dynamicAnalysis.file_operations?.length > 0 && (
                            <div className="card">
                                <div className="card-header">
                                    <h3 className="card-title"><FolderOpen size={20} /> File Operations</h3>
                                </div>
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Operation</th>
                                            <th>Path</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {dynamicAnalysis.file_operations.map((op, i) => (
                                            <tr key={i}>
                                                <td>
                                                    <span className={`badge badge-${op.operation === 'create' ? 'completed' : 'pending'}`}>
                                                        {op.operation}
                                                    </span>
                                                </td>
                                                <td className="mono truncate" style={{ maxWidth: 400 }}>{op.path}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* Registry Operations */}
                        {dynamicAnalysis.registry_operations?.length > 0 && (
                            <div className="card">
                                <div className="card-header">
                                    <h3 className="card-title"><Database size={20} /> Registry Operations</h3>
                                </div>
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Operation</th>
                                            <th>Key</th>
                                            <th>Value</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {dynamicAnalysis.registry_operations.map((op, i) => (
                                            <tr key={i}>
                                                <td>
                                                    <span className={`badge badge-${op.operation === 'create' ? 'completed' : 'pending'}`}>
                                                        {op.operation}
                                                    </span>
                                                </td>
                                                <td className="mono truncate" style={{ maxWidth: 300 }}>{op.key}</td>
                                                <td className="mono">{op.value || '-'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    )
}

export default AnalysisReport
