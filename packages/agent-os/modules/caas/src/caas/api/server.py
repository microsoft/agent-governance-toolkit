# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
REST API for Context-as-a-Service.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

from caas.models import (
    Document,
    DocumentType,
    ContentFormat,
    ContextRequest,
    ContextResponse,
    ContextLayer,
    ContextTriadRequest,
    ContextTriadResponse,
    AddContextRequest,
    RouteRequest,
    RoutingDecision,
    ModelTier,
    AddTurnRequest,
    UpdateTurnRequest,
    ConversationHistoryResponse,
    CreateFileRequest,
    UpdateFileRequest,
    ReadFileRequest,
    DeleteFileRequest,
    ListFilesRequest,
    FileResponse,
    FileListResponse,
)
from caas.ingestion import ProcessorFactory
from caas.detection import DocumentTypeDetector, StructureAnalyzer
from caas.tuning import WeightTuner, CorpusAnalyzer
from caas.storage import DocumentStore, ContextExtractor
from caas.triad import ContextTriadManager
from caas.routing import HeuristicRouter
from caas.conversation import ConversationManager
from caas.gateway import TrustGateway, SecurityPolicy, DeploymentMode
from caas.vfs import VirtualFileSystem


# Initialize FastAPI app
app = FastAPI(
    title="Context-as-a-Service",
    description="Intelligent context extraction and serving",
    version="0.1.0"
)

# Initialize components
document_store = DocumentStore()
detector = DocumentTypeDetector()
structure_analyzer = StructureAnalyzer()
weight_tuner = WeightTuner()
corpus_analyzer = CorpusAnalyzer()
triad_manager = ContextTriadManager()
heuristic_router = HeuristicRouter()
conversation_manager = ConversationManager(max_turns=10)  # Sliding window with 10 turns
# Virtual File System for SDLC agents
vfs = VirtualFileSystem()
# Trust Gateway with enterprise-grade security
trust_gateway = TrustGateway(
    security_policy=SecurityPolicy(
        deployment_mode=DeploymentMode.ON_PREM,
        security_level="high"
    ),
    audit_enabled=True
)
# Note: context_extractor is created per-request with user-specified decay settings


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Context-as-a-Service",
        "version": "0.1.0",
        "status": "operational",
        "endpoints": {
            "ingest": "/ingest",
            "documents": "/documents",
            "context": "/context/{document_id}",
            "analyze": "/analyze/{document_id}",
            "corpus": "/corpus/analyze",
            "route": "/route",
            "triad": "/triad",
            "triad_hot": "/triad/hot",
            "triad_warm": "/triad/warm",
            "triad_cold": "/triad/cold",
            "conversation": "/conversation",
            "conversation_add": "/conversation/turn",
            "conversation_stats": "/conversation/stats",
            "gateway": "/gateway",
            "gateway_route": "/gateway/route",
            "gateway_info": "/gateway/info",
            "gateway_audit": "/gateway/audit",
            "vfs_create": "/vfs/files (POST)",
            "vfs_read": "/vfs/files (GET)",
            "vfs_update": "/vfs/files (PUT)",
            "vfs_delete": "/vfs/files (DELETE)",
            "vfs_list": "/vfs/list",
            "vfs_history": "/vfs/history",
            "vfs_state": "/vfs/state",
        }
    }



@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/ingest")
async def ingest_document(
    file: UploadFile = File(...),
    format: ContentFormat = Form(...),
    title: Optional[str] = Form(None),
    source_type: Optional[str] = Form(None),
    source_url: Optional[str] = Form(None)
):
    """
    Ingest a document for processing.
    
    The service will:
    1. Process the raw content
    2. Auto-detect the document type and structure
    3. Auto-tune weights for sections
    4. Detect or use provided source type for source attribution tracking
    5. Store the processed document
    
    Source Attribution Support:
    - source_type: Explicitly specify source type (official_docs, team_chat, practical_logs, etc.)
    - source_url: Optional URL to the original source
    
    Args:
        file: The file to ingest
        format: The file format (pdf, html, code)
        title: Optional title for the document
        source_type: Optional source type for citation tracking
        source_url: Optional URL to the original source
    
    Returns:
        Processed document information
    """
    try:
        # Read file content
        content = await file.read()
        
        # Generate document ID
        doc_id = str(uuid.uuid4())
        
        # Process the document
        processor = ProcessorFactory.get_processor(format)
        metadata = {
            "id": doc_id,
            "title": title or file.filename,
            "filename": file.filename,
        }
        
        # Add source metadata if provided
        if source_type:
            metadata['source_type'] = source_type
        if source_url:
            metadata['source_url'] = source_url
        
        document = processor.process(content, metadata)
        
        # Auto-detect document type
        detected_type = detector.detect(document)
        document.detected_type = detected_type
        
        # Auto-tune weights
        document = weight_tuner.tune(document)
        
        # Add timestamp
        document.ingestion_timestamp = datetime.now(timezone.utc).isoformat()
        
        # Store document
        document_store.add(document)
        
        # Add to corpus analyzer
        corpus_analyzer.add_document(document)
        
        return {
            "document_id": document.id,
            "title": document.title,
            "detected_type": document.detected_type,
            "format": document.format,
            "sections_found": len(document.sections),
            "weights": document.weights,
            "source_type": source_type or "auto-detected",
            "status": "ingested"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@app.get("/documents")
async def list_documents(doc_type: Optional[DocumentType] = None):
    """
    List all documents or filter by type.
    
    Args:
        doc_type: Optional document type filter
    
    Returns:
        List of documents
    """
    if doc_type:
        documents = document_store.list_by_type(doc_type)
    else:
        documents = document_store.list_all()
    
    return {
        "total": len(documents),
        "documents": [
            {
                "id": doc.id,
                "title": doc.title,
                "type": doc.detected_type,
                "format": doc.format,
                "sections": len(doc.sections),
                "timestamp": doc.ingestion_timestamp,
            }
            for doc in documents
        ]
    }


@app.get("/documents/{document_id}")
async def get_document(document_id: str):
    """
    Get detailed information about a specific document.
    
    Args:
        document_id: The document ID
    
    Returns:
        Document details
    """
    document = document_store.get(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return {
        "id": document.id,
        "title": document.title,
        "type": document.detected_type,
        "format": document.format,
        "sections": [
            {
                "title": s.title,
                "weight": s.weight,
                "importance": s.importance_score,
                "length": len(s.content),
            }
            for s in document.sections
        ],
        "metadata": document.metadata,
        "weights": document.weights,
        "timestamp": document.ingestion_timestamp,
    }


@app.post("/context/{document_id}")
async def get_context(document_id: str, request: ContextRequest):
    """
    Get optimized context from a document.
    
    This endpoint returns the most relevant context based on:
    - Auto-tuned section weights
    - Time-based decay (prioritizes recent content)
    - Optional query for focused extraction
    - Token limits
    - Source citations for transparency (source attribution)
    - Conflict detection between official and practical sources
    
    Source Attribution Philosophy:
    - Provides REAL answers, not just OFFICIAL ones
    - When official docs conflict with practical experience, shows both
    - Includes transparent citations (e.g., "from Slack conversation")
    - Example: "Officially, limit is 100. However, team reports crashes after 50."
    
    Time Decay Formula: Score = Base_Weight * (1 / (1 + days_elapsed * decay_rate))
    Result: Recent documents rank higher than old documents, even with lower similarity.
    
    Args:
        document_id: The document ID
        request: Context request parameters (includes enable_time_decay, decay_rate, enable_citations, detect_conflicts)
    
    Returns:
        Optimized context with time-weighted relevance, citations, and conflict detection
    """
    document = document_store.get(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Create context extractor with requested settings
    extractor = ContextExtractor(
        document_store,
        enrich_metadata=request.include_metadata,
        enable_time_decay=request.enable_time_decay,
        decay_rate=request.decay_rate,
        enable_citations=request.enable_citations,
        detect_conflicts=request.detect_conflicts
    )
    
    # Extract context
    context, metadata = extractor.extract_context(
        document_id,
        request.query,
        request.max_tokens
    )
    
    # Estimate tokens (rough approximation)
    estimated_tokens = len(context) // 4
    
    response = ContextResponse(
        document_id=document_id,
        document_type=document.detected_type,
        context=context,
        sections_used=metadata.get("sections_used", []),
        total_tokens=estimated_tokens,
        weights_applied=metadata.get("weights_applied", {}),
        metadata=metadata if request.include_metadata else {},
        source_citations=metadata.get("citations", []),
        source_conflicts=metadata.get("conflicts", [])
    )
    
    return response


@app.get("/analyze/{document_id}")
async def analyze_document(document_id: str):
    """
    Analyze a document's structure and content.
    
    Args:
        document_id: The document ID
    
    Returns:
        Analysis results
    """
    document = document_store.get(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Perform structure analysis
    structure = detector.detect_structure(document)
    analysis = structure_analyzer.analyze(document)
    
    return {
        "document_id": document_id,
        "structure": structure,
        "analysis": analysis,
    }


@app.get("/corpus/analyze")
async def analyze_corpus():
    """
    Analyze the entire corpus of documents.
    
    Returns insights about:
    - Document type distribution
    - Common section patterns
    - Average weights
    - Optimization suggestions
    
    Returns:
        Corpus analysis results
    """
    analysis = corpus_analyzer.analyze_corpus()
    return analysis


@app.delete("/documents/{document_id}")
async def delete_document(document_id: str):
    """
    Delete a document.
    
    Args:
        document_id: The document ID
    
    Returns:
        Deletion status
    """
    success = document_store.delete(document_id)
    if not success:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return {"status": "deleted", "document_id": document_id}


@app.get("/search")
async def search_documents(
    q: str,
    enable_time_decay: bool = True,
    decay_rate: float = 1.0
):
    """
    Search documents by content or metadata with time-based decay ranking.
    
    When time decay is enabled (default):
    - Recent documents are ranked higher than old documents
    - Formula: relevance_score = match_score * decay_factor
    - Example: Yesterday's 80% match beats Last Year's 95% match
    
    Args:
        q: The search query
        enable_time_decay: Apply time-based decay to ranking (default: True)
        decay_rate: Rate of decay, higher = faster decay (default: 1.0)
    
    Returns:
        Matching documents sorted by time-weighted relevance
    """
    results = document_store.search(
        q,
        enable_time_decay=enable_time_decay,
        decay_rate=decay_rate
    )
    
    return {
        "query": q,
        "enable_time_decay": enable_time_decay,
        "decay_rate": decay_rate,
        "total_results": len(results),
        "documents": [
            {
                "id": doc.id,
                "title": doc.title,
                "type": doc.detected_type,
                "format": doc.format,
                "search_score": doc.metadata.get('_search_score', 0),
                "decay_factor": doc.metadata.get('_decay_factor', 1.0),
                "ingestion_timestamp": doc.ingestion_timestamp,
            }
            for doc in results
        ]
    }


@app.post("/route")
async def route_query(request: RouteRequest):
    """
    Route a query to the appropriate model tier using deterministic heuristics.
    
    The Heuristic Router Philosophy:
    Use Deterministic Heuristics, not AI Classifiers. We can solve 80% of routing 
    with simple logic that takes 0ms. The goal isn't 100% routing accuracy. 
    The goal is instant response time for the trivial stuff, preserving the 
    "Big Brain" budget for the hard stuff.
    
    Routing Rules (in priority order):
    1. Greetings ("Hi", "Thanks") → CANNED response (zero cost, instant)
    2. Smart keywords ("Summarize", "Analyze", "Compare") → SMART model (GPT-4o)
    3. Short queries (< 50 chars) → FAST model (GPT-4o-mini)
    4. Long queries → SMART model (better safe than sorry)
    
    Model Tiers:
    - CANNED: Pre-defined responses for greetings (zero cost, 0ms latency)
    - FAST: Fast model like GPT-4o-mini (low cost, ~200ms latency)
    - SMART: Smart model like GPT-4o (high cost, ~500ms+ latency)
    
    Args:
        request: RouteRequest with the query to route
    
    Returns:
        RoutingDecision with tier, reason, confidence, and suggested model
    """
    try:
        decision = heuristic_router.route(request.query)
        
        # If it's a canned response, include the actual response
        response_data = decision.model_dump()
        if decision.model_tier == ModelTier.CANNED:
            canned_response = heuristic_router.get_canned_response(request.query)
            if canned_response:
                response_data["canned_response"] = canned_response
        
        return response_data
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Routing failed: {str(e)}")



# ===========================
# Tiered Context Endpoints
# ===========================

@app.post("/triad/hot")
async def add_hot_context(request: AddContextRequest):
    """
    Add hot context - the current situation.
    
    Hot context represents what is happening RIGHT NOW:
    - Current conversation messages
    - Open VS Code tabs
    - Error logs streaming in real-time
    - Active debugging session
    
    Policy: "Attention Head" - Hot context overrides everything.
    
    Args:
        request: AddContextRequest with content, metadata, and priority
    
    Returns:
        Created item ID
    """
    try:
        item_id = triad_manager.add_hot_context(
            request.content, 
            request.metadata, 
            request.priority
        )
        return {
            "status": "success",
            "layer": "hot",
            "item_id": item_id,
            "message": "Hot context added successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add hot context: {str(e)}")


@app.post("/triad/warm")
async def add_warm_context(request: AddContextRequest):
    """
    Add warm context - the user persona.
    
    Warm context represents WHO THE USER IS:
    - LinkedIn profile
    - Medium articles
    - GitHub bio
    - Coding style preferences
    - Favorite libraries
    - Communication style
    
    Policy: "Always On Filter" - Warm context is persistent and colors
    how the AI speaks to you.
    
    Args:
        request: AddContextRequest with content, metadata, and priority
    
    Returns:
        Created item ID
    """
    try:
        item_id = triad_manager.add_warm_context(
            request.content, 
            request.metadata, 
            request.priority
        )
        return {
            "status": "success",
            "layer": "warm",
            "item_id": item_id,
            "message": "Warm context added successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add warm context: {str(e)}")


@app.post("/triad/cold")
async def add_cold_context(request: AddContextRequest):
    """
    Add cold context - the historical archive.
    
    Cold context represents WHAT HAPPENED IN THE PAST:
    - Old tickets from last year
    - Closed PRs
    - Historical design docs
    - Legacy system documentation
    - Archived meeting notes
    
    Policy: "On Demand Only" - Cold context is NEVER automatically included.
    It's only fetched when the user explicitly asks for history.
    
    Args:
        request: AddContextRequest with content, metadata, and priority
    
    Returns:
        Created item ID
    """
    try:
        item_id = triad_manager.add_cold_context(
            request.content, 
            request.metadata, 
            request.priority
        )
        return {
            "status": "success",
            "layer": "cold",
            "item_id": item_id,
            "message": "Cold context added successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add cold context: {str(e)}")


@app.post("/triad")
async def get_context_triad(request: ContextTriadRequest):
    """
    Get the complete tiered context.
    
    The tiered context follows these policies:
    1. Hot Context: ALWAYS included (unless explicitly disabled)
       - The Situation: what's happening right now
       - Policy: "Attention Head" - overrides everything
    
    2. Warm Context: ALWAYS ON (unless explicitly disabled)
       - The Persona: who you are
       - Policy: "Filter" - colors how AI speaks to you
    
    3. Cold Context: ON DEMAND ONLY (requires explicit query)
       - The Archive: what happened last year
       - Policy: Never let cold data pollute the hot window
    
    Args:
        request: Tiered context request with layer flags and query
    
    Returns:
        Context from requested layers
    """
    try:
        result = triad_manager.get_full_context(
            include_hot=request.include_hot,
            include_warm=request.include_warm,
            include_cold=request.include_cold,
            cold_query=request.query,
            max_tokens_per_layer=request.max_tokens_per_layer,
            include_metadata=True
        )
        
        response = ContextTriadResponse(
            hot_context=result["hot_context"],
            warm_context=result["warm_context"],
            cold_context=result["cold_context"],
            total_tokens=result["total_tokens"],
            layers_included=result["layers_included"],
            metadata=result["metadata"]
        )
        
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get tiered context: {str(e)}")


@app.get("/triad/state")
async def get_triad_state():
    """
    Get the current state of the tiered context.
    
    Returns:
        Current tiered context state with item counts
    """
    state = triad_manager.get_state()
    return {
        "hot_context_items": len(state.hot_context),
        "warm_context_items": len(state.warm_context),
        "cold_context_items": len(state.cold_context),
        "total_items": len(state.hot_context) + len(state.warm_context) + len(state.cold_context)
    }


@app.delete("/triad/hot")
async def clear_hot_context():
    """Clear all hot context items."""
    triad_manager.clear_hot_context()
    return {"status": "success", "message": "Hot context cleared"}


@app.delete("/triad/warm")
async def clear_warm_context():
    """Clear all warm context items."""
    triad_manager.clear_warm_context()
    return {"status": "success", "message": "Warm context cleared"}


@app.delete("/triad/cold")
async def clear_cold_context():
    """Clear all cold context items."""
    triad_manager.clear_cold_context()
    return {"status": "success", "message": "Cold context cleared"}


@app.delete("/triad")
async def clear_all_context():
    """Clear all context layers."""
    triad_manager.clear_all()
    return {"status": "success", "message": "All context cleared"}


# ===========================
# Conversation Manager Endpoints (Sliding Window / FIFO)
# ===========================

@app.post("/conversation/turn")
async def add_conversation_turn(request: AddTurnRequest):
    """
    Add a conversation turn to the history using Sliding Window (FIFO).
    
    The Brutal Squeeze Philosophy:
    Instead of asking an AI to summarize conversation history (which costs money 
    and loses nuance), we use a brutal "Sliding Window" approach:
    - Keep the last 10 turns perfectly intact
    - Delete turn 11 (FIFO - First In First Out)
    - No summarization = No lossy compression
    
    Why this works:
    - Users rarely refer back to what they said 20 minutes ago
    - They constantly refer to the exact code snippet they pasted 30 seconds ago
    - Summary = Lossy Compression (loses specific error codes, exact wording)
    - Chopping = Lossless Compression (of the recent past)
    
    Example:
    Turn 1: "I tried X and it failed with error code 500"
    With Summarization: "User attempted troubleshooting" (ERROR CODE LOST!)
    With Chopping: After 10 new turns, this is deleted entirely
                   But turns 2-11 are perfectly intact with all details
    
    Args:
        request: AddTurnRequest with user_message, ai_response, and metadata
    
    Returns:
        Created turn ID and current conversation statistics
    """
    try:
        turn_id = conversation_manager.add_turn(
            user_message=request.user_message,
            ai_response=request.ai_response,
            metadata=request.metadata
        )
        
        stats = conversation_manager.get_statistics()
        
        return {
            "status": "success",
            "turn_id": turn_id,
            "message": "Conversation turn added successfully",
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add turn: {str(e)}")


@app.get("/conversation")
async def get_conversation_history(
    format_text: bool = True,
    include_metadata: bool = False
):
    """
    Get the conversation history (last N turns).
    
    Returns the history in FIFO order (oldest to newest).
    All turns are perfectly intact - no summarization, no loss.
    
    The Sliding Window ensures:
    1. Recent precision: Last N turns are perfectly intact
    2. Zero summarization cost: No AI calls needed
    3. No information loss: What's kept is lossless
    4. Predictable behavior: Always know what's in context
    
    Philosophy: In a frugal architecture, we value Recent Precision over Vague History.
    
    Args:
        format_text: If True, return formatted text; if False, return structured data
        include_metadata: Whether to include metadata in text format
    
    Returns:
        Conversation history (formatted or structured)
    """
    try:
        if format_text:
            history_text = conversation_manager.get_conversation_history(
                include_metadata=include_metadata,
                format_as_text=True
            )
            return {"history": history_text}
        else:
            turns = conversation_manager.get_conversation_history(format_as_text=False)
            stats = conversation_manager.get_statistics()
            
            return ConversationHistoryResponse(
                turns=turns,
                total_turns=len(turns),
                max_turns=conversation_manager.state.max_turns,
                total_turns_ever=conversation_manager.state.total_turns_ever,
                oldest_turn_timestamp=turns[0].timestamp if turns else None,
                newest_turn_timestamp=turns[-1].timestamp if turns else None
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")


@app.get("/conversation/stats")
async def get_conversation_statistics():
    """
    Get statistics about the conversation history.
    
    Returns:
        Statistics including current turns, deleted turns, and timestamps
    """
    try:
        stats = conversation_manager.get_statistics()
        return {
            "status": "success",
            "statistics": stats,
            "sliding_window_info": {
                "max_turns": conversation_manager.state.max_turns,
                "policy": "FIFO (First In First Out)",
                "philosophy": "Chopping > Summarizing",
                "benefits": [
                    "Recent precision: Last N turns perfectly intact",
                    "Zero AI cost: No summarization needed",
                    "No information loss: Lossless compression of recent past",
                    "Predictable: Always know what's in context"
                ]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


@app.get("/conversation/recent")
async def get_recent_turns(n: int = 5):
    """
    Get the N most recent conversation turns.
    
    Args:
        n: Number of recent turns to retrieve (default: 5)
    
    Returns:
        Recent conversation turns
    """
    try:
        turns = conversation_manager.get_recent_turns(n=n)
        return {
            "status": "success",
            "recent_turns": turns,
            "count": len(turns),
            "requested": n
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get recent turns: {str(e)}")


@app.patch("/conversation/turn/{turn_id}")
async def update_turn_response(turn_id: str, request: UpdateTurnRequest):
    """
    Update the AI response for a specific turn.
    
    Useful when you add a turn with just the user message
    and want to update it with the AI response later.
    
    Args:
        turn_id: The ID of the turn to update
        request: UpdateTurnRequest with the AI response
    
    Returns:
        Update status
    """
    try:
        success = conversation_manager.update_turn_response(turn_id, request.ai_response)
        if success:
            return {
                "status": "success",
                "turn_id": turn_id,
                "message": "AI response updated successfully"
            }
        else:
            raise HTTPException(status_code=404, detail="Turn not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update turn: {str(e)}")


@app.delete("/conversation")
async def clear_conversation():
    """
    Clear all conversation history.
    
    Note: The total_turns_ever counter is preserved to track
    how many turns have been processed across the lifetime.
    
    Returns:
        Deletion status
    """
    try:
        conversation_manager.clear_conversation()
        return {
            "status": "success",
            "message": "Conversation history cleared",
            "total_turns_ever": conversation_manager.state.total_turns_ever
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear conversation: {str(e)}")


# ===========================
# Trust Gateway Endpoints
# ===========================

@app.get("/gateway")
async def gateway_status():
    """
    Get Trust Gateway status and deployment information.
    
    The Trust Gateway addresses the "Middleware Gap" by providing an
    enterprise-grade, on-premises / private cloud router that CISOs can trust.
    
    Philosophy:
    No Enterprise CISO will send proprietary data to a random middleware startup.
    The Trust Gateway can be deployed within your own infrastructure, ensuring:
    - Data never leaves your environment
    - Full audit trail for compliance
    - Zero third-party data sharing
    - Enterprise-grade security controls
    
    Returns:
        Trust Gateway deployment information and security status
    """
    try:
        info = trust_gateway.get_deployment_info()
        return {
            "status": "operational",
            "gateway_type": "Trust Gateway (Enterprise Private Cloud Router)",
            "philosophy": "The winner won't be the one with the smartest routing; "
                         "it will be the one the Enterprise trusts with the keys to the kingdom.",
            **info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get gateway status: {str(e)}")


@app.post("/gateway/route")
async def gateway_route_request(
    request: RouteRequest,
    user_id: Optional[str] = None,
    data_classification: Optional[str] = None
):
    """
    Route a request through the Trust Gateway with enterprise security controls.
    
    The Trust Gateway provides:
    1. On-Premises / Private Cloud deployment
    2. Zero data leakage (data never leaves your infrastructure)
    3. Full audit trail for compliance
    4. Configurable security policies
    5. Authentication and authorization
    6. Data classification and encryption
    
    This endpoint validates the request against security policies, performs
    heuristic routing, and logs all activity for compliance.
    
    Example Use Case:
    Enterprise CISO requirement: "We cannot send our proprietary financial data
    to an external middleware service." Solution: Deploy Trust Gateway in your
    own infrastructure. All routing decisions happen locally with zero external calls.
    
    Args:
        request: RouteRequest with the query to route
        user_id: User ID making the request (for authentication)
        data_classification: Classification level (public, internal, confidential, secret)
    
    Returns:
        Routing decision with security context and audit trail
    """
    try:
        result = trust_gateway.route_request(
            query=request.query,
            user_id=user_id,
            data_classification=data_classification
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gateway routing failed: {str(e)}")


@app.get("/gateway/info")
async def gateway_deployment_info():
    """
    Get detailed Trust Gateway deployment and security information.
    
    Returns comprehensive information about:
    - Deployment mode (on-prem, private cloud, hybrid, air-gapped)
    - Security level and policies
    - Data retention settings
    - Encryption status
    - Compliance mode
    - Trust guarantees
    
    Returns:
        Detailed deployment and security configuration
    """
    try:
        info = trust_gateway.get_deployment_info()
        return {
            "gateway_info": info,
            "deployment_modes": {
                "on_prem": "Deployed on customer's own servers (maximum control)",
                "private_cloud": "Deployed in customer's private cloud (AWS VPC, Azure VNet, GCP VPC)",
                "hybrid": "Hybrid deployment with local processing and cloud backup",
                "air_gapped": "Completely isolated from internet (maximum security)"
            },
            "security_levels": {
                "standard": "Basic security controls",
                "high": "Enhanced security (encryption at rest and in transit)",
                "maximum": "Maximum security (air-gapped, zero data retention)"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get deployment info: {str(e)}")


@app.get("/gateway/audit")
async def gateway_audit_logs(
    event_type: Optional[str] = None,
    user_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
):
    """
    Retrieve Trust Gateway audit logs for compliance and security monitoring.
    
    Audit logs include:
    - All routing decisions
    - Request validation events
    - Security policy changes
    - Data access events
    - User authentication attempts
    
    This endpoint supports filtering by:
    - Event type (e.g., "request_routed", "policy_changed")
    - User ID
    - Time range (ISO format timestamps)
    
    Example Use Cases:
    - Compliance audits (GDPR, HIPAA, SOC2)
    - Security incident investigation
    - User activity monitoring
    - Policy change tracking
    
    Args:
        event_type: Filter by event type
        user_id: Filter by user ID
        start_time: Start of time range (ISO format)
        end_time: End of time range (ISO format)
    
    Returns:
        Filtered audit log entries
    """
    try:
        logs = trust_gateway.get_audit_logs(
            event_type=event_type,
            user_id=user_id,
            start_time=start_time,
            end_time=end_time
        )
        
        return {
            "status": "success",
            "total_logs": len(logs),
            "filters_applied": {
                "event_type": event_type,
                "user_id": user_id,
                "start_time": start_time,
                "end_time": end_time
            },
            "audit_logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve audit logs: {str(e)}")


@app.post("/gateway/validate")
async def gateway_validate_request(
    query: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    data_classification: Optional[str] = None
):
    """
    Validate a request against Trust Gateway security policies.
    
    This endpoint checks:
    - Authentication requirements
    - User authorization (allowed users list)
    - IP address restrictions
    - Data classification requirements
    - Encryption requirements
    
    Useful for pre-flight validation before sending actual requests.
    
    Args:
        query: The query to validate
        user_id: User ID making the request
        ip_address: IP address of the requester
        data_classification: Data classification level
    
    Returns:
        Validation result with status, warnings, and violations
    """
    try:
        validation = trust_gateway.validate_request(
            request_data={"query": query},
            user_id=user_id,
            ip_address=ip_address,
            data_classification=data_classification
        )
        
        return {
            "status": "success" if validation["valid"] else "failed",
            "valid": validation["valid"],
            "warnings": validation["warnings"],
            "violations": validation["violations"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@app.delete("/gateway/audit")
async def gateway_clear_audit_logs(user_id: Optional[str] = None):
    """
    Clear Trust Gateway audit logs.
    
    Note: This operation itself is logged before clearing.
    Requires proper authorization in production environments.
    
    Args:
        user_id: User ID requesting the clear operation
    
    Returns:
        Clear operation status
    """
    try:
        result = trust_gateway.clear_audit_logs(user_id=user_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear audit logs: {str(e)}")


# ============================================================================
# Virtual File System Endpoints
# ============================================================================

@app.post("/vfs/files", response_model=FileResponse, tags=["vfs"])
async def create_vfs_file(request: CreateFileRequest):
    """
    Create a new file in the Virtual File System.
    
    Allows SDLC agents to create files in shared project state.
    All agents can see files created by other agents.
    """
    try:
        file_node = vfs.create_file(
            path=request.path,
            content=request.content,
            agent_id=request.agent_id,
            metadata=request.metadata,
        )
        
        return FileResponse(
            path=file_node.path,
            file_type=file_node.file_type,
            content=file_node.content,
            metadata=file_node.metadata,
            created_by=file_node.created_by,
            created_at=file_node.created_at,
            modified_by=file_node.modified_by,
            modified_at=file_node.modified_at,
            edit_count=len(file_node.edit_history),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/vfs/files", response_model=FileResponse, tags=["vfs"])
async def read_vfs_file(path: str):
    """
    Read a file from the Virtual File System.
    
    Agents can read files created or modified by other agents,
    ensuring shared visibility of project state.
    """
    try:
        content = vfs.read_file(path)
        info = vfs.get_file_info(path)
        return info
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/vfs/files", response_model=FileResponse, tags=["vfs"])
async def update_vfs_file(request: UpdateFileRequest):
    """
    Update an existing file in the Virtual File System.
    
    Agents can update files and other agents will immediately see
    the changes. Edit history is maintained for auditability.
    """
    try:
        file_node = vfs.update_file(
            path=request.path,
            content=request.content,
            agent_id=request.agent_id,
            message=request.message,
        )
        
        return FileResponse(
            path=file_node.path,
            file_type=file_node.file_type,
            content=file_node.content,
            metadata=file_node.metadata,
            created_by=file_node.created_by,
            created_at=file_node.created_at,
            modified_by=file_node.modified_by,
            modified_at=file_node.modified_at,
            edit_count=len(file_node.edit_history),
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/vfs/files", tags=["vfs"])
async def delete_vfs_file(path: str, agent_id: str):
    """
    Delete a file from the Virtual File System.
    
    Removes a file from the shared project state.
    """
    try:
        vfs.delete_file(path, agent_id)
        return {"status": "deleted", "path": path}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/vfs/list", response_model=FileListResponse, tags=["vfs"])
async def list_vfs_files(path: str = "/", recursive: bool = False):
    """
    List files in a directory within the Virtual File System.
    
    Agents can browse the project structure to understand
    what files exist and have been created by other agents.
    """
    try:
        return vfs.list_files(path, recursive)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/vfs/history", tags=["vfs"])
async def get_vfs_file_history(path: str):
    """
    Get the edit history of a file.
    
    Shows all edits made to a file, including which agents
    made changes and when. Useful for understanding how a
    file evolved through multi-agent collaboration.
    """
    try:
        history = vfs.get_file_history(path)
        return {
            "path": path,
            "edit_count": len(history),
            "history": [
                {
                    "agent_id": edit.agent_id,
                    "timestamp": edit.timestamp,
                    "message": edit.message,
                    "content_preview": edit.content[:100] + "..." if len(edit.content) > 100 else edit.content,
                }
                for edit in history
            ]
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/vfs/state", tags=["vfs"])
async def get_vfs_state():
    """
    Get the complete Virtual File System state.
    
    Returns the entire file system state, useful for debugging
    or snapshotting the current project state.
    """
    state = vfs.get_state()
    return {
        "root_path": state.root_path,
        "file_count": len(state.files),
        "files": [
            {
                "path": node.path,
                "type": node.file_type,
                "created_by": node.created_by,
                "modified_by": node.modified_by,
                "edit_count": len(node.edit_history),
            }
            for node in state.files.values()
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
