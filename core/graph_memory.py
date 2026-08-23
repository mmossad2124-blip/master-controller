import networkx as nx
from typing import Dict, List, Any

class GraphMemoryManager:
    """Combines Structural Knowledge Graphs with Vector DB embeddings to prevent hallucinations."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_code_node(self, node_id: str, node_type: str, attributes: Dict[str, Any]):
        """Adds a code structure node (Function, Endpoint, Class, Module)."""
        self.graph.add_node(node_id, node_type=node_type, **attributes)

    def add_relationship(self, source_id: str, target_id: str, relation: str):
        """Adds structural relationship (e.g., ENDPOINT_CALLS_FUNCTION, FUNCTION_USES_INPUT)."""
        self.graph.add_edge(source_id, target_id, relation=relation)

    def query_subgraph(self, node_id: str) -> Dict[str, Any]:
        """Retrieves 2-hop structural context around a specified code node."""
        if not self.graph.has_node(node_id):
            return {"node": node_id, "neighbors": []}
        
        subgraph_nodes = nx.single_source_shortest_path_length(self.graph, node_id, cutoff=2)
        sub_g = self.graph.subgraph(subgraph_nodes)
        
        return {
            "node": node_id,
            "nodes": [data for n, data in sub_g.nodes(data=True)],
            "edges": [(u, v, data) for u, v, data in sub_g.edges(data=True)]
        }
