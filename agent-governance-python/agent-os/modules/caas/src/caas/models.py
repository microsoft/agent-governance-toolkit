# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Data models for Context-as-a-Service.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ContentTier(str, Enum):
    """Content importance tiers for structure-aware indexing."""
    TIER_1_HIGH = "tier_1_high"  # High Value: Titles, Headers, Class Definitions, API Contracts
    TIER_2_MEDIUM = "tier_2_medium"  # Medium Value: Body text, Function logic
    TIER_3_LOW = "tier_3_low"  # Low Value: Footnotes, Comments, Disclaimers


class ContextLayer(str, Enum):
    """Context tiers defined by intimacy and access policy."""
    HOT = "hot"  # L1: The Situation - current conversation, active data (overrides everything)
    WARM = "warm"  # L2: The Persona - user profile, preferences (always-on filter)
    COLD = "cold"  # L3: The Archive - historical data (on-demand only)


class DocumentType(str, Enum):
    """Detected document types."""
    LEGAL_CONTRACT = "legal_contract"
    TECHNICAL_DOCUMENTATION = "technical_documentation"
    SOURCE_CODE = "source_code"
    RESEARCH_PAPER = "research_paper"
    ARTICLE = "article"
    TUTORIAL = "tutorial"
    API_DOCUMENTATION = "api_documentation"
    UNKNOWN = "unknown"


class ContentFormat(str, Enum):
    """Supported content formats."""
    PDF = "pdf"
    HTML = "html"
    CODE = "code"
    MARKDOWN = "markdown"
    TEXT = "text"


class SourceType(str, Enum):
    """Source types."""
    OFFICIAL_DOCS = "official_docs"  # Official documentation, specs, formal docs
    PRACTICAL_LOGS = "practical_logs"  # Server logs, error logs, system logs
    TEAM_CHAT = "team_chat"  # Slack, Teams, chat conversations
    CODE_COMMENTS = "code_comments"  # Inline code comments and TODOs
    TICKET_SYSTEM = "ticket_system"  # Jira, GitHub issues, bug reports
    RUNBOOK = "runbook"  # Operational runbooks, troubleshooting guides
    WIKI = "wiki"  # Internal wiki, knowledge base
    MEETING_NOTES = "meeting_notes"  # Meeting notes, decisions
    UNKNOWN = "unknown"  # Unknown or unspecified source


class SourceCitation(BaseModel):
    """Citation for source tracking."""
    source_type: SourceType
    source_name: str  # e.g., "API Documentation v2.1", "Slack #engineering 2024-01-03"
    source_url: Optional[str] = None  # Link to original source if available
    timestamp: Optional[str] = None  # When the information was created/updated
    excerpt: Optional[str] = None  # Brief excerpt from source
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)  # Confidence in the information (0-1)


class Section(BaseModel):
    """Represents a section of a document."""
    title: str
    content: str
    weight: float = 1.0
    tier: Optional['ContentTier'] = None
    importance_score: float = 0.0
    start_pos: int = 0
    end_pos: int = 0
    parent_section: Optional[str] = None  # Parent section title for hierarchical context
    chapter: Optional[str] = None  # Chapter or major section name
    source_citation: Optional[SourceCitation] = None  # Citation for source tracking


class Document(BaseModel):
    """Represents a processed document."""
    id: str
    title: str
    content: str
    format: ContentFormat
    detected_type: DocumentType
    sections: List[Section] = []
    metadata: Dict[str, Any] = {}
    weights: Dict[str, float] = {}
    ingestion_timestamp: Optional[str] = None
    source_citation: Optional[SourceCitation] = None  # Document-level citation


class ContextRequest(BaseModel):
    """Request for context extraction."""
    document_id: Optional[str] = None
    query: str
    max_tokens: int = Field(default=2000, gt=0, le=10000)
    include_metadata: bool = True
    enable_time_decay: bool = Field(
        default=True, 
        description="Apply time-based decay to prioritize recent content (default: True)"
    )
    decay_rate: float = Field(
        default=1.0, 
        ge=0.01, 
        le=10.0,
        description="Rate of time decay. Higher = faster decay (default: 1.0)"
    )
    enable_citations: bool = Field(
        default=True,
        description="Include source citations for transparency (default: True)"
    )
    detect_conflicts: bool = Field(
        default=True,
        description="Detect conflicts between official and practical sources (default: True)"
    )


class ContextResponse(BaseModel):
    """Response containing extracted context."""
    document_id: str
    document_type: DocumentType
    context: str
    sections_used: List[str] = []
    total_tokens: int
    weights_applied: Dict[str, float] = {}
    metadata: Dict[str, Any] = {}
    source_citations: List[SourceCitation] = Field(
        default=[],
        description="Citations for all sources used in the context"
    )
    source_conflicts: List[Dict[str, Any]] = Field(
        default=[],
        description="Conflicts between official and practical sources"
    )


class ContextTriadItem(BaseModel):
    """Represents an item in a context layer."""
    id: str
    layer: ContextLayer
    content: str
    metadata: Dict[str, Any] = {}
    timestamp: Optional[str] = None
    priority: float = 1.0


class ContextTriadState(BaseModel):
    """Represents the complete tiered context state."""
    hot_context: List[ContextTriadItem] = []  # Current situation (conversation, errors)
    warm_context: List[ContextTriadItem] = []  # User persona (profile, preferences)
    cold_context: List[ContextTriadItem] = []  # Historical archive (old tickets, PRs)
    
    
class ContextTriadRequest(BaseModel):
    """Request for tiered context retrieval."""
    include_hot: bool = Field(default=True, description="Include hot context (current situation)")
    include_warm: bool = Field(default=True, description="Include warm context (user persona)")
    include_cold: bool = Field(default=False, description="Include cold context (historical archive) - on-demand only")
    max_tokens_per_layer: Dict[str, int] = Field(
        default={"hot": 1000, "warm": 500, "cold": 1000},
        description="Token limits per layer"
    )
    query: Optional[str] = Field(default=None, description="Optional query for cold context retrieval")


class AddContextRequest(BaseModel):
    """Request for adding context to a layer."""
    content: str = Field(description="The context content to add")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Optional metadata")
    priority: float = Field(default=1.0, ge=0.0, le=10.0, description="Priority level (0-10)")


class ContextTriadResponse(BaseModel):
    """Response containing tiered context data."""
    hot_context: str = ""
    warm_context: str = ""
    cold_context: str = ""
    total_tokens: int
    layers_included: List[str]
    metadata: Dict[str, Any] = {}


class SourceConflict(BaseModel):
    """Represents a conflict between official and practical sources."""
    topic: str  # What the conflict is about
    official_answer: str  # What official docs say
    official_source: SourceCitation  # Citation for official answer
    practical_answer: str  # What practical sources say (logs, chat, etc.)
    practical_source: SourceCitation  # Citation for practical answer
    recommendation: str  # Which to trust and why
    conflict_severity: str = Field(
        default="medium",
        description="Severity: low, medium, high"
    )


class ModelTier(str, Enum):
    """Model tiers for heuristic routing decisions."""
    CANNED = "canned"  # Canned response, zero cost
    FAST = "fast"  # Fast model (e.g., GPT-4o-mini)
    SMART = "smart"  # Smart model (e.g., GPT-4o)


class RoutingDecision(BaseModel):
    """Represents a routing decision made by the heuristic router."""
    model_config = {'protected_namespaces': ()}  # Avoid pydantic warning for model_tier
    
    model_tier: ModelTier
    reason: str  # Why this tier was chosen
    confidence: float = Field(ge=0.0, le=1.0)  # Confidence in the decision (0-1)
    query_length: int  # Length of the query
    matched_keywords: List[str] = []  # Keywords that triggered the decision
    suggested_model: str  # Suggested model name (e.g., "gpt-4o-mini", "gpt-4o")
    estimated_cost: str  # Estimated cost category (zero, low, medium, high)


class RouteRequest(BaseModel):
    """Request for routing a query to the appropriate model."""
    query: str = Field(description="The user query to route")


class ConversationTurn(BaseModel):
    """Represents a single turn in a conversation (user message + AI response)."""
    id: str
    user_message: str
    ai_response: Optional[str] = None
    timestamp: str
    metadata: Dict[str, Any] = {}


class ConversationState(BaseModel):
    """Represents the conversation history with sliding window."""
    turns: List[ConversationTurn] = []
    max_turns: int = Field(default=10, ge=1, le=100)
    total_turns_ever: int = 0  # Track total turns including deleted ones


class AddTurnRequest(BaseModel):
    """Request to add a conversation turn."""
    user_message: str = Field(description="The user's message")
    ai_response: Optional[str] = Field(default=None, description="The AI's response (optional)")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional metadata")


class UpdateTurnRequest(BaseModel):
    """Request to update a turn's AI response."""
    ai_response: str = Field(description="The AI response to add/update")


class ConversationHistoryResponse(BaseModel):
    """Response containing conversation history."""
    turns: List[ConversationTurn]
    total_turns: int
    max_turns: int
    total_turns_ever: int
    oldest_turn_timestamp: Optional[str] = None
    newest_turn_timestamp: Optional[str] = None


# ============================================================================
# Virtual File System Models
# ============================================================================


class FileType(str, Enum):
    """Types of file system nodes."""
    FILE = "file"
    DIRECTORY = "directory"


class FileEdit(BaseModel):
    """Represents an edit to a file."""
    agent_id: str = Field(description="ID of the agent that made the edit")
    timestamp: str = Field(description="ISO timestamp of the edit")
    content: str = Field(description="Content after this edit")
    message: Optional[str] = Field(default=None, description="Optional commit-like message")


class FileNode(BaseModel):
    """Represents a file or directory in the virtual file system."""
    path: str = Field(description="Full path of the file/directory")
    file_type: FileType = Field(description="Type of node (file or directory)")
    content: str = Field(default="", description="Content of the file (empty for directories)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_by: str = Field(description="Agent ID that created this file")
    created_at: str = Field(description="ISO timestamp of creation")
    modified_by: str = Field(description="Agent ID that last modified this file")
    modified_at: str = Field(description="ISO timestamp of last modification")
    edit_history: List[FileEdit] = Field(default_factory=list, description="History of edits")


class VFSState(BaseModel):
    """Represents the complete virtual file system state."""
    files: Dict[str, FileNode] = Field(
        default_factory=dict,
        description="Mapping of file paths to FileNode objects"
    )
    root_path: str = Field(default="/", description="Root path of the file system")


class CreateFileRequest(BaseModel):
    """Request to create a file in the VFS."""
    path: str = Field(description="Path of the file to create")
    content: str = Field(default="", description="Initial content of the file")
    agent_id: str = Field(description="ID of the agent creating the file")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional metadata")


class UpdateFileRequest(BaseModel):
    """Request to update a file in the VFS."""
    path: str = Field(description="Path of the file to update")
    content: str = Field(description="New content of the file")
    agent_id: str = Field(description="ID of the agent updating the file")
    message: Optional[str] = Field(default=None, description="Optional commit-like message")


class ReadFileRequest(BaseModel):
    """Request to read a file from the VFS."""
    path: str = Field(description="Path of the file to read")


class DeleteFileRequest(BaseModel):
    """Request to delete a file from the VFS."""
    path: str = Field(description="Path of the file to delete")
    agent_id: str = Field(description="ID of the agent deleting the file")


class ListFilesRequest(BaseModel):
    """Request to list files in the VFS."""
    path: str = Field(default="/", description="Path to list files from")
    recursive: bool = Field(default=False, description="Whether to list files recursively")


class FileResponse(BaseModel):
    """Response containing file information."""
    path: str
    file_type: FileType
    content: str
    metadata: Dict[str, Any]
    created_by: str
    created_at: str
    modified_by: str
    modified_at: str
    edit_count: int = Field(description="Number of edits made to this file")


class FileListResponse(BaseModel):
    """Response containing a list of files."""
    files: List[FileResponse]
    total_count: int
