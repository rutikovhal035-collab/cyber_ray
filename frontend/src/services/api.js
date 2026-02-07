import axios from 'axios'

const API_BASE_URL = '/api'

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
})

// Analysis endpoints
export const analysisAPI = {
    // Submit file for analysis
    submitFile: async (file, options = {}) => {
        const formData = new FormData()
        formData.append('file', file)
        if (options.timeout) {
            formData.append('timeout', options.timeout)
        }

        const response = await api.post('/analysis/submit', formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
        })
        return response.data
    },

    // Get analysis status
    getStatus: async (taskId) => {
        const response = await api.get(`/analysis/status/${taskId}`)
        return response.data
    },

    // Get full analysis report
    getReport: async (taskId) => {
        const response = await api.get(`/analysis/report/${taskId}`)
        return response.data
    },

    // List all analyses
    listAnalyses: async (params = {}) => {
        const response = await api.get('/analysis/list', { params })
        return response.data
    },

    // Delete analysis
    deleteAnalysis: async (taskId) => {
        const response = await api.delete(`/analysis/${taskId}`)
        return response.data
    },
}

// YARA endpoints
export const yaraAPI = {
    // Generate YARA rule from analysis
    generateRule: async (taskId, options = {}) => {
        const response = await api.post('/yara/generate', {
            task_id: taskId,
            rule_name: options.ruleName,
            include_strings: options.includeStrings ?? true,
            include_imports: options.includeImports ?? true,
            include_hashes: options.includeHashes ?? true,
        })
        return response.data
    },

    // List all YARA rules
    listRules: async (params = {}) => {
        const response = await api.get('/yara/rules', { params })
        return response.data
    },

    // Get specific YARA rule
    getRule: async (ruleId) => {
        const response = await api.get(`/yara/rules/${ruleId}`)
        return response.data
    },

    // Update YARA rule
    updateRule: async (ruleId, data) => {
        const response = await api.put(`/yara/rules/${ruleId}`, data)
        return response.data
    },

    // Delete YARA rule
    deleteRule: async (ruleId) => {
        const response = await api.delete(`/yara/rules/${ruleId}`)
        return response.data
    },

    // Validate YARA syntax
    validateRule: async (ruleContent) => {
        const response = await api.post('/yara/validate', { rule_content: ruleContent })
        return response.data
    },

    // Test YARA rule against sample
    testRule: async (ruleId, taskId) => {
        const response = await api.post(`/yara/test/${ruleId}`, null, {
            params: { task_id: taskId },
        })
        return response.data
    },
}

// Reports endpoints
export const reportsAPI = {
    // Export report
    exportReport: async (taskId, format = 'json') => {
        const response = await api.get(`/reports/export/${taskId}`, {
            params: { format },
            responseType: format === 'json' ? 'json' : 'blob',
        })
        return response.data
    },

    // Get statistics
    getStatistics: async (days = 30) => {
        const response = await api.get('/reports/statistics', {
            params: { days },
        })
        return response.data
    },
}

// Health check
export const healthCheck = async () => {
    const response = await api.get('/health')
    return response.data
}

export default api
