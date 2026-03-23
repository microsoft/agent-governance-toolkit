# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Graph Debugger - Visual Trace Generator for Mute Agent

Generates visual artifacts showing:
- Green Path: Nodes traversed successfully
- Red Node: The exact node where constraint failed
- Grey Nodes: Unreachable parts of the graph

This proves "Deterministic Safety" - showing where the agent physically
could not reach certain nodes because the path was severed.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

VISUALIZATION_AVAILABLE = NETWORKX_AVAILABLE and (PYVIS_AVAILABLE or MATPLOTLIB_AVAILABLE)


class NodeState(Enum):
    """States a node can be in during execution."""
    SUCCESS = "success"  # Green - traversed successfully
    FAILURE = "failure"  # Red - constraint failed here
    UNREACHABLE = "unreachable"  # Grey - could not be reached
    PENDING = "pending"  # Not yet visited


@dataclass
class ExecutionTrace:
    """Tracks execution path through the knowledge graph."""
    session_id: str
    action_id: str
    traversed_nodes: List[str] = field(default_factory=list)
    failed_node: Optional[str] = None
    node_states: Dict[str, NodeState] = field(default_factory=dict)
    edge_traversals: List[tuple] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class GraphDebugger:
    """
    The Graph Debugger generates visual artifacts for every execution.
    Shows deterministic safety by visualizing which paths were accessible.
    """
    
    def __init__(self, knowledge_graph=None):
        """
        Initialize the Graph Debugger.
        
        Args:
            knowledge_graph: The MultidimensionalKnowledgeGraph to visualize
        """
        self.knowledge_graph = knowledge_graph
        self.traces: List[ExecutionTrace] = []
        
        if not VISUALIZATION_AVAILABLE:
            missing = []
            if not NETWORKX_AVAILABLE:
                missing.append("networkx")
            if not PYVIS_AVAILABLE:
                missing.append("pyvis")
            if not MATPLOTLIB_AVAILABLE:
                missing.append("matplotlib")
            print(f"Warning: Visualization libraries not available: {', '.join(missing)}")
            print("Install with: pip install matplotlib networkx pyvis")
    
    def create_trace(
        self,
        session_id: str,
        action_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ExecutionTrace:
        """Create a new execution trace."""
        trace = ExecutionTrace(
            session_id=session_id,
            action_id=action_id,
            metadata=metadata or {}
        )
        self.traces.append(trace)
        return trace
    
    def record_node_visit(self, trace: ExecutionTrace, node_id: str, success: bool):
        """Record a node visit in the trace."""
        trace.traversed_nodes.append(node_id)
        if success:
            trace.node_states[node_id] = NodeState.SUCCESS
        else:
            trace.node_states[node_id] = NodeState.FAILURE
            trace.failed_node = node_id
    
    def record_edge_traversal(self, trace: ExecutionTrace, source_id: str, target_id: str):
        """Record an edge traversal."""
        trace.edge_traversals.append((source_id, target_id))
    
    def mark_unreachable_nodes(self, trace: ExecutionTrace, all_node_ids: List[str]):
        """Mark nodes that were not reached as unreachable."""
        reached = set(trace.traversed_nodes)
        for node_id in all_node_ids:
            if node_id not in reached and node_id not in trace.node_states:
                trace.node_states[node_id] = NodeState.UNREACHABLE
    
    def visualize_trace(
        self,
        trace: ExecutionTrace,
        output_path: str = "execution_trace.html",
        format: str = "html"
    ) -> str:
        """
        Generate a visual artifact for the execution trace.
        
        Args:
            trace: The execution trace to visualize
            output_path: Where to save the visualization
            format: 'html' (interactive) or 'png' (static image)
        
        Returns:
            Path to the generated visualization
        """
        if not VISUALIZATION_AVAILABLE:
            print("Cannot generate visualization: libraries not installed")
            return ""
        
        if format == "html":
            return self._generate_interactive_html(trace, output_path)
        elif format == "png":
            return self._generate_static_png(trace, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_interactive_html(self, trace: ExecutionTrace, output_path: str) -> str:
        """Generate an interactive HTML visualization using pyvis."""
        # Create a directed graph
        net = Network(
            height="750px",
            width="100%",
            directed=True,
            notebook=False,
            bgcolor="#ffffff",
            font_color="#000000"
        )
        
        # Configure physics for better layout
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -8000,
              "centralGravity": 0.3,
              "springLength": 150,
              "springConstant": 0.04
            }
          },
          "nodes": {
            "font": {
              "size": 16,
              "face": "arial"
            }
          },
          "edges": {
            "arrows": {
              "to": {
                "enabled": true,
                "scaleFactor": 0.5
              }
            },
            "smooth": {
              "type": "continuous"
            }
          }
        }
        """)
        
        # Add nodes with colors based on state
        for node_id, state in trace.node_states.items():
            color, title = self._get_node_style(node_id, state, trace)
            
            # Make failed node stand out
            if state == NodeState.FAILURE:
                net.add_node(
                    node_id,
                    label=node_id,
                    color=color,
                    title=title,
                    size=30,
                    borderWidth=3,
                    borderWidthSelected=4
                )
            else:
                net.add_node(
                    node_id,
                    label=node_id,
                    color=color,
                    title=title,
                    size=20
                )
        
        # Add edges from knowledge graph if available
        if self.knowledge_graph:
            self._add_edges_from_knowledge_graph(net, trace)
        else:
            # Add edges from trace
            for source, target in trace.edge_traversals:
                # Check if edge was part of success or failure path
                edge_color = "#2ecc71" if source in trace.traversed_nodes else "#95a5a6"
                net.add_edge(source, target, color=edge_color, width=2)
        
        # Add legend as HTML title
        html_legend = self._create_html_legend(trace)
        
        # Generate the HTML
        net.save_graph(output_path)
        
        # Insert legend into HTML
        self._inject_legend_into_html(output_path, html_legend)
        
        print(f"Interactive visualization saved to: {output_path}")
        return output_path
    
    def _generate_static_png(self, trace: ExecutionTrace, output_path: str) -> str:
        """Generate a static PNG visualization using matplotlib and networkx."""
        # Create a directed graph
        G = nx.DiGraph()
        
        # Add nodes
        for node_id in trace.node_states.keys():
            G.add_node(node_id)
        
        # Add edges
        if self.knowledge_graph:
            # Extract edges from knowledge graph
            for dim_name, subgraph in self.knowledge_graph.subgraphs.items():
                for edge in subgraph.edges:
                    if edge.source_id in G.nodes and edge.target_id in G.nodes:
                        G.add_edge(edge.source_id, edge.target_id)
        else:
            for source, target in trace.edge_traversals:
                G.add_edge(source, target)
        
        # Create figure
        plt.figure(figsize=(14, 10))
        
        # Use hierarchical layout
        try:
            pos = nx.spring_layout(G, k=2, iterations=50)
        except (ValueError, RuntimeError) as e:
            logger.debug("spring_layout failed, falling back to shell_layout: %s", e)
            pos = nx.shell_layout(G)
        
        # Draw nodes with colors based on state
        for state in NodeState:
            nodes = [n for n, s in trace.node_states.items() if s == state]
            if nodes:
                color, label = self._get_node_color_for_png(state)
                nx.draw_networkx_nodes(
                    G, pos,
                    nodelist=nodes,
                    node_color=color,
                    node_size=1000 if state == NodeState.FAILURE else 700,
                    label=label,
                    alpha=0.9
                )
        
        # Draw edges
        nx.draw_networkx_edges(
            G, pos,
            edge_color='#95a5a6',
            arrows=True,
            arrowsize=20,
            width=2,
            alpha=0.6
        )
        
        # Highlight traversed edges
        traversed_edges = [(s, t) for s, t in trace.edge_traversals if G.has_edge(s, t)]
        if traversed_edges:
            nx.draw_networkx_edges(
                G, pos,
                edgelist=traversed_edges,
                edge_color='#2ecc71',
                arrows=True,
                arrowsize=20,
                width=3,
                alpha=0.9
            )
        
        # Draw labels
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')
        
        # Add title and legend
        plt.title(
            f"Execution Trace: {trace.action_id}\n"
            f"Session: {trace.session_id}",
            fontsize=14,
            fontweight='bold',
            pad=20
        )
        
        plt.legend(loc='upper left', fontsize=10)
        plt.axis('off')
        plt.tight_layout()
        
        # Save
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        print(f"Static visualization saved to: {output_path}")
        return output_path
    
    def _get_node_style(self, node_id: str, state: NodeState, trace: ExecutionTrace) -> tuple:
        """Get node color and title based on state."""
        if state == NodeState.SUCCESS:
            color = "#2ecc71"  # Green
            title = f"{node_id}\n✓ Traversed successfully"
        elif state == NodeState.FAILURE:
            color = "#e74c3c"  # Red
            errors = "\n".join(trace.validation_errors) if trace.validation_errors else "Constraint failed"
            title = f"{node_id}\n✗ FAILED\n{errors}"
        elif state == NodeState.UNREACHABLE:
            color = "#95a5a6"  # Grey
            title = f"{node_id}\n○ Unreachable (path severed)"
        else:
            color = "#3498db"  # Blue
            title = f"{node_id}\n○ Pending"
        
        return color, title
    
    def _get_node_color_for_png(self, state: NodeState) -> tuple:
        """Get node color and label for PNG visualization."""
        if state == NodeState.SUCCESS:
            return "#2ecc71", "Success (Traversed)"
        elif state == NodeState.FAILURE:
            return "#e74c3c", "Failure (Constraint Violated)"
        elif state == NodeState.UNREACHABLE:
            return "#95a5a6", "Unreachable (Path Severed)"
        else:
            return "#3498db", "Pending"
    
    def _add_edges_from_knowledge_graph(self, net, trace: ExecutionTrace):
        """Add edges from the knowledge graph to the visualization."""
        if not self.knowledge_graph:
            return
        
        traversed = set(trace.traversed_nodes)
        
        for dim_name, subgraph in self.knowledge_graph.subgraphs.items():
            for edge in subgraph.edges:
                # Only add edges between nodes that are in the trace
                if edge.source_id in trace.node_states and edge.target_id in trace.node_states:
                    # Color based on whether edge was traversed
                    if edge.source_id in traversed:
                        color = "#2ecc71"  # Green for traversed
                        width = 3
                    else:
                        color = "#95a5a6"  # Grey for not traversed
                        width = 1
                    
                    title = f"{edge.edge_type.value}: {edge.source_id} → {edge.target_id}"
                    net.add_edge(
                        edge.source_id,
                        edge.target_id,
                        color=color,
                        width=width,
                        title=title
                    )
    
    def _create_html_legend(self, trace: ExecutionTrace) -> str:
        """Create HTML legend for the visualization."""
        success_count = sum(1 for s in trace.node_states.values() if s == NodeState.SUCCESS)
        failure_count = sum(1 for s in trace.node_states.values() if s == NodeState.FAILURE)
        unreachable_count = sum(1 for s in trace.node_states.values() if s == NodeState.UNREACHABLE)
        
        legend = f"""
        <div style="position: absolute; top: 10px; right: 10px; background: white; 
                    padding: 15px; border: 2px solid #ccc; border-radius: 5px; 
                    font-family: Arial; max-width: 300px;">
            <h3 style="margin: 0 0 10px 0;">Execution Trace Legend</h3>
            <p style="margin: 5px 0;"><span style="color: #2ecc71;">●</span> <strong>Green:</strong> Traversed successfully ({success_count})</p>
            <p style="margin: 5px 0;"><span style="color: #e74c3c;">●</span> <strong>Red:</strong> Constraint failed ({failure_count})</p>
            <p style="margin: 5px 0;"><span style="color: #95a5a6;">●</span> <strong>Grey:</strong> Unreachable ({unreachable_count})</p>
            <hr style="margin: 10px 0;">
            <p style="margin: 5px 0; font-size: 12px;"><strong>Session:</strong> {trace.session_id}</p>
            <p style="margin: 5px 0; font-size: 12px;"><strong>Action:</strong> {trace.action_id}</p>
            {f'<p style="margin: 5px 0; font-size: 12px; color: #e74c3c;"><strong>Failed at:</strong> {trace.failed_node}</p>' if trace.failed_node else ''}
        </div>
        """
        return legend
    
    def _inject_legend_into_html(self, html_path: str, legend_html: str):
        """Inject legend HTML into the generated visualization."""
        try:
            with open(html_path, 'r') as f:
                html_content = f.read()
            
            # Insert legend before closing body tag
            html_content = html_content.replace('</body>', f'{legend_html}</body>')
            
            with open(html_path, 'w') as f:
                f.write(html_content)
        except FileNotFoundError:
            print(f"Warning: Could not find HTML file: {html_path}")
        except PermissionError:
            print(f"Warning: Permission denied writing to: {html_path}")
        except Exception as e:
            print(f"Warning: Could not inject legend: {type(e).__name__}: {e}")
    
    def generate_comparison_visualization(
        self,
        traces: List[ExecutionTrace],
        output_path: str = "trace_comparison.png"
    ) -> str:
        """
        Generate a side-by-side comparison of multiple traces.
        Useful for showing how different contexts lead to different paths.
        """
        if not VISUALIZATION_AVAILABLE:
            print("Cannot generate visualization: libraries not installed")
            return ""
        
        num_traces = len(traces)
        fig, axes = plt.subplots(1, num_traces, figsize=(7 * num_traces, 6))
        
        if num_traces == 1:
            axes = [axes]
        
        for idx, trace in enumerate(traces):
            ax = axes[idx]
            
            # Create graph for this trace
            G = nx.DiGraph()
            for node_id in trace.node_states.keys():
                G.add_node(node_id)
            for source, target in trace.edge_traversals:
                G.add_edge(source, target)
            
            # Layout
            try:
                pos = nx.spring_layout(G, k=1.5, iterations=50)
            except (ValueError, RuntimeError) as e:
                logger.debug("spring_layout failed, falling back to shell_layout: %s", e)
                pos = nx.shell_layout(G)
            
            # Draw nodes
            for state in NodeState:
                nodes = [n for n, s in trace.node_states.items() if s == state]
                if nodes:
                    color, _ = self._get_node_color_for_png(state)
                    nx.draw_networkx_nodes(
                        G, pos,
                        nodelist=nodes,
                        node_color=color,
                        node_size=500,
                        alpha=0.9,
                        ax=ax
                    )
            
            # Draw edges
            nx.draw_networkx_edges(G, pos, edge_color='#95a5a6', 
                                  arrows=True, arrowsize=15, width=1.5, 
                                  alpha=0.6, ax=ax)
            
            # Draw labels
            nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold', ax=ax)
            
            ax.set_title(f"Trace {idx + 1}: {trace.action_id}", fontweight='bold')
            ax.axis('off')
        
        plt.suptitle("Execution Trace Comparison", fontsize=16, fontweight='bold')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        print(f"Comparison visualization saved to: {output_path}")
        return output_path
