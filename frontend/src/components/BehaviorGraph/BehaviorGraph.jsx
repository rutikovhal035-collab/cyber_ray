import { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import * as d3 from 'd3'
import { ArrowLeft, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'
import { analysisAPI } from '../../services/api'
import './BehaviorGraph.css'

function BehaviorGraph() {
    const { taskId } = useParams()
    const svgRef = useRef(null)
    const containerRef = useRef(null)
    const [loading, setLoading] = useState(true)
    const [graphData, setGraphData] = useState(null)

    useEffect(() => {
        loadGraphData()
    }, [taskId])

    useEffect(() => {
        if (graphData && svgRef.current) {
            renderGraph()
        }
    }, [graphData])

    const loadGraphData = async () => {
        try {
            setLoading(true)
            // Use mock data for demo
            setGraphData(getMockGraphData())
        } finally {
            setLoading(false)
        }
    }

    const getMockGraphData = () => ({
        nodes: [
            { id: 'sample', label: 'suspicious.exe', type: 'sample' },
            { id: 'proc_1234', label: 'suspicious.exe', type: 'process' },
            { id: 'proc_1235', label: 'cmd.exe', type: 'process' },
            { id: 'proc_1236', label: 'powershell.exe', type: 'process' },
            { id: 'net_1', label: 'malicious-c2.com', type: 'network' },
            { id: 'net_2', label: '192.168.1.100:443', type: 'network' },
            { id: 'file_1', label: 'payload.dll', type: 'file' },
            { id: 'file_2', label: 'hosts', type: 'file' },
            { id: 'reg_1', label: 'Run', type: 'registry' },
            { id: 'api_filesystem', label: 'File APIs (23)', type: 'api' },
            { id: 'api_network', label: 'Network APIs (8)', type: 'api' },
            { id: 'api_process', label: 'Process APIs (12)', type: 'api' },
        ],
        links: [
            { source: 'sample', target: 'proc_1234', label: 'executed' },
            { source: 'proc_1234', target: 'proc_1235', label: 'spawned' },
            { source: 'proc_1235', target: 'proc_1236', label: 'spawned' },
            { source: 'proc_1234', target: 'net_1', label: 'TCP:443' },
            { source: 'proc_1234', target: 'net_2', label: 'connect' },
            { source: 'proc_1234', target: 'file_1', label: 'create' },
            { source: 'proc_1234', target: 'file_2', label: 'modify' },
            { source: 'proc_1234', target: 'reg_1', label: 'modify' },
            { source: 'sample', target: 'api_filesystem', label: 'calls' },
            { source: 'sample', target: 'api_network', label: 'calls' },
            { source: 'sample', target: 'api_process', label: 'calls' },
        ]
    })

    const nodeColors = {
        sample: '#ec4899',
        process: '#3b82f6',
        file: '#22c55e',
        network: '#ef4444',
        registry: '#f59e0b',
        api: '#8b5cf6'
    }

    const renderGraph = () => {
        const container = containerRef.current
        const width = container.clientWidth
        const height = container.clientHeight

        // Clear previous graph
        d3.select(svgRef.current).selectAll('*').remove()

        const svg = d3.select(svgRef.current)
            .attr('width', width)
            .attr('height', height)

        // Create zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.2, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform)
            })

        svg.call(zoom)

        const g = svg.append('g')

        // Arrow marker for edges
        svg.append('defs').append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '-0 -5 10 10')
            .attr('refX', 20)
            .attr('refY', 0)
            .attr('orient', 'auto')
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .append('path')
            .attr('d', 'M 0,-5 L 10,0 L 0,5')
            .attr('fill', '#64748b')

        // Create simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(120))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(50))

        // Create links
        const link = g.append('g')
            .selectAll('line')
            .data(graphData.links)
            .enter()
            .append('line')
            .attr('stroke', '#334155')
            .attr('stroke-width', 2)
            .attr('marker-end', 'url(#arrowhead)')

        // Link labels
        const linkLabel = g.append('g')
            .selectAll('text')
            .data(graphData.links)
            .enter()
            .append('text')
            .text(d => d.label)
            .attr('font-size', '10px')
            .attr('fill', '#64748b')
            .attr('text-anchor', 'middle')

        // Create nodes
        const node = g.append('g')
            .selectAll('g')
            .data(graphData.nodes)
            .enter()
            .append('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended)
            )

        // Node circles
        node.append('circle')
            .attr('r', d => d.type === 'sample' ? 25 : 18)
            .attr('fill', d => nodeColors[d.type])
            .attr('stroke', '#0f172a')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')

        // Node labels
        node.append('text')
            .text(d => d.label.length > 12 ? d.label.substring(0, 12) + '...' : d.label)
            .attr('dy', 35)
            .attr('text-anchor', 'middle')
            .attr('font-size', '11px')
            .attr('fill', '#f1f5f9')
            .attr('font-weight', 500)

        // Node icons (emoji for simplicity)
        node.append('text')
            .text(d => {
                const icons = {
                    sample: '🎯', process: '📦', file: '📄',
                    network: '🌐', registry: '🗃️', api: '⚡'
                }
                return icons[d.type] || '●'
            })
            .attr('text-anchor', 'middle')
            .attr('dy', 5)
            .attr('font-size', '14px')

        // Simulation tick
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y)

            linkLabel
                .attr('x', d => (d.source.x + d.target.x) / 2)
                .attr('y', d => (d.source.y + d.target.y) / 2)

            node.attr('transform', d => `translate(${d.x},${d.y})`)
        })

        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            event.subject.fx = event.subject.x
            event.subject.fy = event.subject.y
        }

        function dragged(event) {
            event.subject.fx = event.x
            event.subject.fy = event.y
        }

        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0)
            event.subject.fx = null
            event.subject.fy = null
        }

        // Store zoom for controls
        window.graphZoom = zoom
        window.graphSvg = svg
    }

    const handleZoomIn = () => {
        if (window.graphSvg && window.graphZoom) {
            window.graphSvg.transition().call(window.graphZoom.scaleBy, 1.3)
        }
    }

    const handleZoomOut = () => {
        if (window.graphSvg && window.graphZoom) {
            window.graphSvg.transition().call(window.graphZoom.scaleBy, 0.7)
        }
    }

    const handleResetZoom = () => {
        if (window.graphSvg && window.graphZoom) {
            window.graphSvg.transition().call(window.graphZoom.transform, d3.zoomIdentity)
        }
    }

    if (loading) {
        return <div className="loading"><div className="spinner"></div></div>
    }

    return (
        <div className="behavior-graph-page animate-fade-in">
            <div className="graph-header">
                <Link to={`/analysis/${taskId}`} className="back-link">
                    <ArrowLeft size={20} />
                    Back to Report
                </Link>
                <h1>Behavior Graph</h1>
            </div>

            <div className="graph-container card">
                <div className="graph-controls">
                    <button className="btn btn-secondary" onClick={handleZoomIn}>
                        <ZoomIn size={18} />
                    </button>
                    <button className="btn btn-secondary" onClick={handleZoomOut}>
                        <ZoomOut size={18} />
                    </button>
                    <button className="btn btn-secondary" onClick={handleResetZoom}>
                        <Maximize2 size={18} />
                    </button>
                </div>

                <div className="graph-legend">
                    {Object.entries(nodeColors).map(([type, color]) => (
                        <div key={type} className="legend-item">
                            <span className="legend-dot" style={{ backgroundColor: color }}></span>
                            <span className="legend-label">{type}</span>
                        </div>
                    ))}
                </div>

                <div className="graph-canvas" ref={containerRef}>
                    <svg ref={svgRef}></svg>
                </div>
            </div>
        </div>
    )
}

export default BehaviorGraph
