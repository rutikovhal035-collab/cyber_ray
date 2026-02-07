import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDropzone } from 'react-dropzone'
import {
    Upload,
    File,
    AlertCircle,
    CheckCircle,
    X,
    Loader
} from 'lucide-react'
import { analysisAPI } from '../../services/api'
import './FileUpload.css'

function FileUpload() {
    const navigate = useNavigate()
    const [file, setFile] = useState(null)
    const [uploading, setUploading] = useState(false)
    const [uploadStatus, setUploadStatus] = useState(null)
    const [error, setError] = useState(null)
    const [analysisTimeout, setAnalysisTimeout] = useState(300)

    const onDrop = useCallback((acceptedFiles) => {
        if (acceptedFiles.length > 0) {
            setFile(acceptedFiles[0])
            setError(null)
            setUploadStatus(null)
        }
    }, [])

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop,
        multiple: false,
        maxSize: 50 * 1024 * 1024, // 50MB
        onDropRejected: (rejectedFiles) => {
            const rejection = rejectedFiles[0]
            if (rejection.errors[0]?.code === 'file-too-large') {
                setError('File is too large. Maximum size is 50MB.')
            } else {
                setError('File could not be uploaded.')
            }
        }
    })

    const handleSubmit = async () => {
        if (!file) return

        setUploading(true)
        setError(null)

        try {
            const result = await analysisAPI.submitFile(file, { timeout: analysisTimeout })
            setUploadStatus({
                success: true,
                taskId: result.task_id,
                message: 'File submitted successfully!'
            })

            // Redirect to analysis page after 2 seconds
            setTimeout(() => {
                navigate(`/analysis/${result.task_id}`)
            }, 2000)
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to submit file for analysis.')
            setUploadStatus({ success: false })
        } finally {
            setUploading(false)
        }
    }

    const removeFile = () => {
        setFile(null)
        setError(null)
        setUploadStatus(null)
    }

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 Bytes'
        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }

    return (
        <div className="file-upload-page animate-fade-in">
            <div className="upload-header">
                <h1>Upload Sample</h1>
                <p className="text-muted">Submit a file for malware analysis</p>
            </div>

            <div className="card upload-card">
                {/* Dropzone */}
                <div
                    {...getRootProps()}
                    className={`dropzone ${isDragActive ? 'active' : ''} ${file ? 'has-file' : ''}`}
                >
                    <input {...getInputProps()} />

                    {!file ? (
                        <>
                            <Upload className="dropzone-icon" size={64} />
                            <p className="dropzone-text">
                                {isDragActive
                                    ? 'Drop the file here...'
                                    : 'Drag & drop a file here, or click to select'
                                }
                            </p>
                            <p className="dropzone-subtext">
                                Maximum file size: 50MB
                            </p>
                        </>
                    ) : (
                        <div className="selected-file">
                            <File size={48} className="file-icon" />
                            <div className="file-info">
                                <span className="file-name">{file.name}</span>
                                <span className="file-size">{formatFileSize(file.size)}</span>
                            </div>
                            <button
                                className="btn btn-icon remove-file"
                                onClick={(e) => { e.stopPropagation(); removeFile(); }}
                            >
                                <X size={20} />
                            </button>
                        </div>
                    )}
                </div>

                {/* Analysis Options */}
                {file && !uploadStatus?.success && (
                    <div className="upload-options">
                        <div className="option-group">
                            <label htmlFor="timeout">Analysis Timeout (seconds)</label>
                            <input
                                type="number"
                                id="timeout"
                                value={analysisTimeout}
                                onChange={(e) => setAnalysisTimeout(parseInt(e.target.value) || 300)}
                                min={60}
                                max={600}
                            />
                        </div>
                    </div>
                )}

                {/* Error Message */}
                {error && (
                    <div className="upload-message error">
                        <AlertCircle size={20} />
                        <span>{error}</span>
                    </div>
                )}

                {/* Success Message */}
                {uploadStatus?.success && (
                    <div className="upload-message success">
                        <CheckCircle size={20} />
                        <span>{uploadStatus.message} Redirecting to analysis...</span>
                    </div>
                )}

                {/* Submit Button */}
                {file && !uploadStatus?.success && (
                    <button
                        className="btn btn-primary submit-btn"
                        onClick={handleSubmit}
                        disabled={uploading}
                    >
                        {uploading ? (
                            <>
                                <Loader size={18} className="spinner-icon" />
                                Uploading...
                            </>
                        ) : (
                            <>
                                <Upload size={18} />
                                Start Analysis
                            </>
                        )}
                    </button>
                )}
            </div>

            {/* Info Cards */}
            <div className="info-cards">
                <div className="card info-card">
                    <h4>📊 Static Analysis</h4>
                    <p>Hash calculation, PE analysis, string extraction, and suspicious pattern detection</p>
                </div>
                <div className="card info-card">
                    <h4>🔬 Dynamic Analysis</h4>
                    <p>Behavioral analysis in isolated sandbox, API call tracing, network activity monitoring</p>
                </div>
                <div className="card info-card">
                    <h4>📝 YARA Generation</h4>
                    <p>Automatic YARA rule generation based on analysis results for threat detection</p>
                </div>
            </div>
        </div>
    )
}

export default FileUpload
