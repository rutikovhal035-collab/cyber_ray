"""
Behavior Graph Builder
Creates graph data structures for visualizing malware behavior
"""

from typing import Dict, List, Any, Optional
from app.models.schemas import (
    BehaviorGraph,
    BehaviorGraphNode,
    BehaviorGraphEdge
)


class BehaviorGraphBuilder:
    """Builds behavior graphs from analysis results for D3.js visualization"""
    
    # Node type colors (for frontend reference)
    NODE_COLORS = {
        "process": "#3b82f6",    # Blue
        "file": "#22c55e",       # Green
        "registry": "#f59e0b",   # Amber
        "network": "#ef4444",    # Red
        "api": "#8b5cf6",        # Purple
        "sample": "#ec4899",     # Pink
    }
    
    def build_graph(
        self,
        static_analysis: Optional[Dict[str, Any]],
        dynamic_analysis: Optional[Dict[str, Any]]
    ) -> BehaviorGraph:
        """
        Build a complete behavior graph from analysis results
        
        Args:
            static_analysis: Static analysis results
            dynamic_analysis: Dynamic analysis results (from CAPEv2)
            
        Returns:
            BehaviorGraph with nodes and edges for visualization
        """
        nodes = []
        edges = []
        node_ids = set()
        
        # Add sample node (root)
        sample_node = BehaviorGraphNode(
            id="sample",
            label="Analyzed Sample",
            type="sample",
            properties={
                "file_type": static_analysis.get("file_type", "Unknown") if static_analysis else "Unknown",
                "threat_level": "high"
            }
        )
        nodes.append(sample_node)
        node_ids.add("sample")
        
        if dynamic_analysis:
            # Add process nodes
            processes = dynamic_analysis.get("processes", [])
            for proc in processes:
                proc_id = f"proc_{proc.get('pid', 0)}"
                if proc_id not in node_ids:
                    nodes.append(BehaviorGraphNode(
                        id=proc_id,
                        label=proc.get("name", "unknown.exe"),
                        type="process",
                        properties={
                            "pid": proc.get("pid"),
                            "ppid": proc.get("ppid"),
                            "path": proc.get("path"),
                            "command_line": proc.get("command_line")
                        }
                    ))
                    node_ids.add(proc_id)
                    
                    # Connect to parent
                    if proc.get("ppid"):
                        parent_id = f"proc_{proc['ppid']}"
                        if parent_id in node_ids:
                            edges.append(BehaviorGraphEdge(
                                source=parent_id,
                                target=proc_id,
                                label="spawned",
                                properties={"type": "process_creation"}
                            ))
                        else:
                            # Connect to sample node
                            edges.append(BehaviorGraphEdge(
                                source="sample",
                                target=proc_id,
                                label="executed",
                                properties={"type": "execution"}
                            ))
            
            # Add file operation nodes
            file_ops = dynamic_analysis.get("file_operations", [])
            file_count = {}
            for op in file_ops[:30]:  # Limit to prevent graph overload
                path = op.get("path", "")
                if not path:
                    continue
                
                # Extract filename for cleaner labels
                filename = path.split("\\")[-1] if "\\" in path else path.split("/")[-1]
                file_id = f"file_{hash(path) % 10000}"
                
                if file_id not in node_ids:
                    nodes.append(BehaviorGraphNode(
                        id=file_id,
                        label=filename[:30],
                        type="file",
                        properties={
                            "full_path": path,
                            "operation": op.get("operation")
                        }
                    ))
                    node_ids.add(file_id)
                    file_count[file_id] = 0
                
                file_count[file_id] = file_count.get(file_id, 0) + 1
                
                # Connect to process
                proc_id = f"proc_{op.get('process_id', 0)}"
                source = proc_id if proc_id in node_ids else "sample"
                
                edges.append(BehaviorGraphEdge(
                    source=source,
                    target=file_id,
                    label=op.get("operation", "access"),
                    properties={"type": "file_operation"}
                ))
            
            # Add network nodes
            network_activity = dynamic_analysis.get("network_activity", [])
            for conn in network_activity[:20]:
                dst = conn.get("dst_ip", "")
                domain = conn.get("domain", "")
                
                net_id = f"net_{hash(dst + domain) % 10000}"
                
                if net_id not in node_ids:
                    label = domain if domain else dst
                    nodes.append(BehaviorGraphNode(
                        id=net_id,
                        label=label[:30],
                        type="network",
                        properties={
                            "ip": dst,
                            "port": conn.get("dst_port"),
                            "domain": domain,
                            "protocol": conn.get("protocol")
                        }
                    ))
                    node_ids.add(net_id)
                    
                    # Connect to sample (simplified - could connect to specific process)
                    edges.append(BehaviorGraphEdge(
                        source="sample",
                        target=net_id,
                        label=f"{conn.get('protocol', 'TCP')}:{conn.get('dst_port', 0)}",
                        properties={"type": "network_connection"}
                    ))
            
            # Add registry nodes
            reg_ops = dynamic_analysis.get("registry_operations", [])
            for op in reg_ops[:20]:
                key = op.get("key", "")
                if not key:
                    continue
                
                # Simplify key for label
                key_short = key.split("\\")[-1] if "\\" in key else key
                reg_id = f"reg_{hash(key) % 10000}"
                
                if reg_id not in node_ids:
                    nodes.append(BehaviorGraphNode(
                        id=reg_id,
                        label=key_short[:30],
                        type="registry",
                        properties={
                            "full_key": key,
                            "value": op.get("value"),
                            "data": op.get("data"),
                            "operation": op.get("operation")
                        }
                    ))
                    node_ids.add(reg_id)
                    
                    edges.append(BehaviorGraphEdge(
                        source="sample",
                        target=reg_id,
                        label=op.get("operation", "access"),
                        properties={"type": "registry_operation"}
                    ))
            
            # Add API category nodes for summarization
            api_categories = self._group_api_calls(dynamic_analysis.get("api_calls", []))
            for category, apis in api_categories.items():
                api_id = f"api_{category}"
                if api_id not in node_ids:
                    nodes.append(BehaviorGraphNode(
                        id=api_id,
                        label=f"{category.title()} APIs ({len(apis)})",
                        type="api",
                        properties={
                            "category": category,
                            "calls": [a.get("api_name") for a in apis[:10]],
                            "count": len(apis)
                        }
                    ))
                    node_ids.add(api_id)
                    
                    edges.append(BehaviorGraphEdge(
                        source="sample",
                        target=api_id,
                        label="calls",
                        properties={"type": "api_usage", "count": len(apis)}
                    ))
        
        # Deduplicate edges
        edges = self._deduplicate_edges(edges)
        
        return BehaviorGraph(nodes=nodes, edges=edges)
    
    def _group_api_calls(self, api_calls: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group API calls by category"""
        groups = {}
        for call in api_calls:
            category = call.get("category", "other")
            if category not in groups:
                groups[category] = []
            groups[category].append(call)
        return groups
    
    def _deduplicate_edges(self, edges: List[BehaviorGraphEdge]) -> List[BehaviorGraphEdge]:
        """Remove duplicate edges"""
        seen = set()
        unique = []
        
        for edge in edges:
            key = (edge.source, edge.target, edge.label)
            if key not in seen:
                seen.add(key)
                unique.append(edge)
        
        return unique
    
    def to_d3_format(self, graph: BehaviorGraph) -> Dict[str, Any]:
        """
        Convert BehaviorGraph to D3.js force-directed graph format
        
        Returns format expected by D3:
        {
            "nodes": [{"id": "...", "label": "...", "group": "..."}],
            "links": [{"source": "...", "target": "...", "value": 1}]
        }
        """
        d3_nodes = [
            {
                "id": node.id,
                "label": node.label,
                "group": node.type,
                "color": self.NODE_COLORS.get(node.type, "#999999"),
                **node.properties
            }
            for node in graph.nodes
        ]
        
        d3_links = [
            {
                "source": edge.source,
                "target": edge.target,
                "label": edge.label,
                "value": 1,
                **edge.properties
            }
            for edge in graph.edges
        ]
        
        return {
            "nodes": d3_nodes,
            "links": d3_links
        }
    
    def get_graph_summary(self, graph: BehaviorGraph) -> Dict[str, Any]:
        """Get summary statistics for the behavior graph"""
        node_types = {}
        for node in graph.nodes:
            node_types[node.type] = node_types.get(node.type, 0) + 1
        
        edge_types = {}
        for edge in graph.edges:
            edge_type = edge.properties.get("type", "unknown")
            edge_types[edge_type] = edge_types.get(edge_type, 0) + 1
        
        return {
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "node_types": node_types,
            "edge_types": edge_types
        }
