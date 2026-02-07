import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
    FileCode,
    Play,
    Copy,
    Download,
    CheckCircle,
    AlertCircle,
    Trash2,
    Plus
} from 'lucide-react'
import { yaraAPI, analysisAPI } from '../../services/api'
import './YARAGenerator.css'

function YARAGenerator() {
    const [searchParams] = useSearchParams()
    const [analyses, setAnalyses] = useState([])
    const [selectedTask, setSelectedTask] = useState(searchParams.get('task') || '')
    const [rules, setRules] = useState([])
    const [generatedRule, setGeneratedRule] = useState('')
    const [loading, setLoading] = useState(false)
    const [generating, setGenerating] = useState(false)
    const [options, setOptions] = useState({
        ruleName: '',
        includeStrings: true,
        includeImports: true,
        includeHashes: true
    })
    const [message, setMessage] = useState(null)

    useEffect(() => {
        loadData()
    }, [])

    const loadData = async () => {
        setLoading(true)
        try {
            // Try API, fallback to mock
            try {
                const [analysesData, rulesData] = await Promise.all([
                    analysisAPI.listAnalyses({ status: 'completed' }),
                    yaraAPI.listRules()
                ])
                setAnalyses(analysesData.tasks || [])
                setRules(rulesData || [])
            } catch {
                setAnalyses([
                    { task_id: 'abc123', filename: 'suspicious.exe', threat_level: 'high' },
                    { task_id: 'def456', filename: 'trojan.dll', threat_level: 'critical' },
                    { task_id: 'ghi789', filename: 'malware.pdf', threat_level: 'medium' },
                ])
                setRules([
                    { id: 'rule1', name: 'malware_abc123', description: 'Auto-generated rule', created_at: '2026-02-07T10:00:00' },
                    { id: 'rule2', name: 'trojan_detector', description: 'Trojan detection rule', created_at: '2026-02-06T14:30:00' },
                ])
            }
        } finally {
            setLoading(false)
        }
    }

    const handleGenerate = async () => {
        if (!selectedTask) {
            setMessage({ type: 'error', text: 'Please select an analysis task' })
            return
        }

        setGenerating(true)
        setMessage(null)

        try {
            try {
                const rule = await yaraAPI.generateRule(selectedTask, options)
                setGeneratedRule(rule.rule_content)
                setMessage({ type: 'success', text: 'YARA rule generated successfully!' })
                loadData() // Refresh rules list
            } catch {
                // Mock generated rule
                const mockRule = generateMockRule()
                setGeneratedRule(mockRule)
                setMessage({ type: 'success', text: 'YARA rule generated successfully! (Demo)' })
            }
        } finally {
            setGenerating(false)
        }
    }

    const generateMockRule = () => {
        const name = options.ruleName || `malware_${selectedTask.substring(0, 8)}`
        return `rule ${name} {
    meta:
        author = "Malware Analysis Sandbox"
        date = "${new Date().toISOString().split('T')[0]}"
        description = "Auto-generated rule from analysis ${selectedTask}"
        ${options.includeHashes ? `hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"` : ''}

    strings:
        $str_0 = "http://malicious-c2.com/beacon" ascii wide nocase
        $str_1 = "cmd.exe /c whoami" ascii wide nocase
        $str_2 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide nocase
        ${options.includeImports ? `$imp_0 = "VirtualAlloc" ascii
        $imp_1 = "CreateRemoteThread" ascii
        $imp_2 = "GetAsyncKeyState" ascii` : ''}

    condition:
        uint16(0) == 0x5A4D and 3 of them
}`
    }

    const handleCopy = () => {
        navigator.clipboard.writeText(generatedRule)
        setMessage({ type: 'success', text: 'Copied to clipboard!' })
        setTimeout(() => setMessage(null), 2000)
    }

    const handleDownload = () => {
        const blob = new Blob([generatedRule], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${options.ruleName || 'yara_rule'}.yar`
        a.click()
        URL.revokeObjectURL(url)
    }

    if (loading) {
        return <div className="loading"><div className="spinner"></div></div>
    }

    return (
        <div className="yara-generator animate-fade-in">
            <div className="yara-header">
                <div>
                    <h1>YARA Rule Generator</h1>
                    <p className="text-muted">Generate YARA rules from malware analysis</p>
                </div>
            </div>

            <div className="yara-content">
                {/* Generator Panel */}
                <div className="card generator-panel">
                    <div className="card-header">
                        <h3 className="card-title">
                            <Plus size={20} />
                            Generate New Rule
                        </h3>
                    </div>

                    <div className="generator-form">
                        <div className="form-group">
                            <label>Select Analysis</label>
                            <select
                                value={selectedTask}
                                onChange={(e) => setSelectedTask(e.target.value)}
                            >
                                <option value="">-- Select a completed analysis --</option>
                                {analyses.map(a => (
                                    <option key={a.task_id} value={a.task_id}>
                                        {a.filename} ({a.threat_level})
                                    </option>
                                ))}
                            </select>
                        </div>

                        <div className="form-group">
                            <label>Rule Name (optional)</label>
                            <input
                                type="text"
                                placeholder="e.g., trojan_detector"
                                value={options.ruleName}
                                onChange={(e) => setOptions({ ...options, ruleName: e.target.value })}
                            />
                        </div>

                        <div className="form-group checkbox-group">
                            <label className="checkbox-label">
                                <input
                                    type="checkbox"
                                    checked={options.includeStrings}
                                    onChange={(e) => setOptions({ ...options, includeStrings: e.target.checked })}
                                />
                                Include suspicious strings
                            </label>
                            <label className="checkbox-label">
                                <input
                                    type="checkbox"
                                    checked={options.includeImports}
                                    onChange={(e) => setOptions({ ...options, includeImports: e.target.checked })}
                                />
                                Include suspicious imports
                            </label>
                            <label className="checkbox-label">
                                <input
                                    type="checkbox"
                                    checked={options.includeHashes}
                                    onChange={(e) => setOptions({ ...options, includeHashes: e.target.checked })}
                                />
                                Include file hashes in metadata
                            </label>
                        </div>

                        <button
                            className="btn btn-primary generate-btn"
                            onClick={handleGenerate}
                            disabled={generating || !selectedTask}
                        >
                            {generating ? (
                                <>
                                    <span className="spinner" style={{ width: 18, height: 18 }}></span>
                                    Generating...
                                </>
                            ) : (
                                <>
                                    <FileCode size={18} />
                                    Generate YARA Rule
                                </>
                            )}
                        </button>
                    </div>

                    {message && (
                        <div className={`message ${message.type}`}>
                            {message.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
                            {message.text}
                        </div>
                    )}
                </div>

                {/* Generated Rule */}
                {generatedRule && (
                    <div className="card rule-output">
                        <div className="card-header">
                            <h3 className="card-title">
                                <FileCode size={20} />
                                Generated Rule
                            </h3>
                            <div className="rule-actions">
                                <button className="btn btn-secondary" onClick={handleCopy}>
                                    <Copy size={16} />
                                    Copy
                                </button>
                                <button className="btn btn-primary" onClick={handleDownload}>
                                    <Download size={16} />
                                    Download
                                </button>
                            </div>
                        </div>
                        <div className="code-block yara-code">
                            <pre>{generatedRule}</pre>
                        </div>
                    </div>
                )}

                {/* Saved Rules */}
                <div className="card saved-rules">
                    <div className="card-header">
                        <h3 className="card-title">
                            <FileCode size={20} />
                            Saved Rules
                        </h3>
                    </div>

                    {rules.length > 0 ? (
                        <table className="table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Description</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rules.map(rule => (
                                    <tr key={rule.id}>
                                        <td className="mono">{rule.name}</td>
                                        <td className="text-muted">{rule.description}</td>
                                        <td className="text-muted">
                                            {new Date(rule.created_at).toLocaleDateString()}
                                        </td>
                                        <td>
                                            <div className="flex gap-sm">
                                                <button className="btn btn-icon" title="Test rule">
                                                    <Play size={16} />
                                                </button>
                                                <button className="btn btn-icon" title="Delete rule">
                                                    <Trash2 size={16} />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <div className="text-center text-muted" style={{ padding: '2rem' }}>
                            No saved rules yet. Generate your first rule above.
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

export default YARAGenerator
