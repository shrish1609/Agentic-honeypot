"""
core/graph.py — Assembles all nodes into the LangGraph DAG.

Graph topology:
  START → intake → strategy → persona → extractor → guard → END
                                                        ↑
                              (conditional: continue loops back via caller,
                               end closes session — both route to END here
                               since the caller handles the conversation loop)
"""

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from core.state import HoneypotState
from core.nodes import (
    intake_node,
    strategy_node,
    persona_node,
    extractor_node,
    guard_node,
    route_after_guard,
)
from core.reporter import reporter_node


def build_graph(use_memory: bool = True):
    """
    Build and compile the Agentic Honeypot LangGraph.

    Args:
        use_memory: If True, attaches MemorySaver for multi-turn session persistence.
                    Each session uses a unique thread_id for isolation.
                    Set False for stateless single-turn testing.

    Returns:
        Compiled LangGraph application.
    """
    builder = StateGraph(HoneypotState)

    # Register nodes
    builder.add_node("intake", intake_node)
    builder.add_node("strategy", strategy_node)
    builder.add_node("persona", persona_node)
    builder.add_node("extractor", extractor_node)
    builder.add_node("guard", guard_node)
    builder.add_node("reporter", reporter_node)

    # Linear edges
    builder.add_edge(START, "intake")
    builder.add_edge("intake", "strategy")
    builder.add_edge("strategy", "persona")
    builder.add_edge("persona", "extractor")
    builder.add_edge("extractor", "guard")

    # Conditional exit
    # Both branches pass through the reporter before ending the turn.
    builder.add_conditional_edges(
        "guard",
        route_after_guard,
        {"continue": "reporter", "end": "reporter"},
    )
    builder.add_edge("reporter", END)

    checkpointer = MemorySaver() if use_memory else None
    return builder.compile(checkpointer=checkpointer)


# Singleton — import this in session_manager and tests
honeypot_graph = build_graph(use_memory=True)