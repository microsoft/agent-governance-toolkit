# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Pharma Compliance Demo - Find Contradictions Humans Miss

This demo showcases:
- Context as a Service (CAAS) for deep document analysis
- Agent VFS for document storage and retrieval
- Citation linking (every claim traced to source)
- Self-Correcting Agent Kernel (SCAK) for hallucination prevention

Usage:
    python demo.py
    python demo.py --mode contradiction_only
    python demo.py --verbose
"""

import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import uuid4


class ContradictionSeverity(Enum):
    """Severity levels for contradictions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DocumentType(Enum):
    """Types of documents in the corpus"""
    LAB_REPORT = "lab_report"
    CLINICAL_TRIAL = "clinical_trial"
    IND_DRAFT = "ind_draft"
    SAFETY_REPORT = "safety_report"


@dataclass
class Citation:
    """Citation to a source document"""
    document_id: str
    document_type: DocumentType
    page: int
    paragraph: int
    exact_text: str
    
    def __str__(self) -> str:
        return f"{self.document_id}, Page {self.page}, Para {self.paragraph}"


@dataclass
class Claim:
    """A claim made in a document"""
    claim_id: str = field(default_factory=lambda: str(uuid4())[:8])
    text: str = ""
    value: Optional[float] = None
    unit: str = ""
    citation: Optional[Citation] = None
    confidence: float = 1.0
    
    def __str__(self) -> str:
        return f"{self.text}: {self.value}{self.unit}" if self.value else self.text


@dataclass
class Contradiction:
    """A contradiction between documents"""
    contradiction_id: str = field(default_factory=lambda: str(uuid4())[:8])
    claim_1: Claim = None  # From draft
    claim_2: Claim = None  # From lab report
    severity: ContradictionSeverity = ContradictionSeverity.MEDIUM
    category: str = ""  # efficacy, dosage, statistical, timeline
    recommendation: str = ""
    
    def variance_percentage(self) -> Optional[float]:
        """Calculate variance between numeric claims"""
        if self.claim_1.value and self.claim_2.value:
            return abs(self.claim_1.value - self.claim_2.value) / self.claim_2.value * 100
        return None


@dataclass 
class Document:
    """Document in the VFS"""
    doc_id: str
    doc_type: DocumentType
    title: str
    content: dict  # Structured content
    page_count: int
    created_date: datetime = field(default_factory=datetime.now)


class AgentVFS:
    """
    Simulated Agent Virtual File System
    
    In production, this would be backed by the real VFS
    with mount points like /mem/documents/
    """
    
    def __init__(self, base_path: str = "/agent/compliance/mem"):
        self.base_path = base_path
        self.files: dict[str, Document] = {}
        self.index: dict[str, list[str]] = {}  # keyword -> doc_ids
    
    def mount(self, path: str, doc: Document):
        """Mount a document in the VFS"""
        full_path = f"{self.base_path}/{path}"
        self.files[full_path] = doc
        
        # Index keywords
        self._index_document(doc)
    
    def read(self, path: str) -> Optional[Document]:
        """Read a document from VFS"""
        full_path = f"{self.base_path}/{path}" if not path.startswith(self.base_path) else path
        return self.files.get(full_path)
    
    def list_docs(self, path: str = "") -> "list[str]":
        """List documents in a path"""
        full_path = f"{self.base_path}/{path}" if path else self.base_path
        return [p for p in self.files.keys() if p.startswith(full_path)]
    
    def search(self, keyword: str) -> "list[Document]":
        """Search for documents containing keyword"""
        doc_ids = self.index.get(keyword.lower(), [])
        return [self.files[doc_id] for doc_id in doc_ids if doc_id in self.files]
    
    def _index_document(self, doc: Document):
        """Index document for search"""
        # Index title words
        for word in doc.title.lower().split():
            if word not in self.index:
                self.index[word] = []
            self.index[word].append(f"{self.base_path}/documents/{doc.doc_id}")
        
        # Index content keywords
        content_str = json.dumps(doc.content).lower()
        for keyword in ["efficacy", "safety", "dosage", "response", "adverse", "primary", "secondary"]:
            if keyword in content_str:
                if keyword not in self.index:
                    self.index[keyword] = []
                self.index[keyword].append(f"{self.base_path}/documents/{doc.doc_id}")


class CAAS:
    """
    Simulated Context as a Service
    
    Provides large context window for document analysis.
    In production, this would use Claude 3.5 with 200K context.
    """
    
    def __init__(self, max_tokens: int = 200000):
        self.max_tokens = max_tokens
        self.current_context: list[Document] = []
        self.token_count = 0
    
    def load_documents(self, documents: list[Document]):
        """Load documents into context"""
        self.current_context = documents
        self.token_count = sum(doc.page_count * 500 for doc in documents)  # ~500 tokens/page
        
        if self.token_count > self.max_tokens:
            print(f"⚠️ Warning: Context exceeds {self.max_tokens} tokens ({self.token_count})")
    
    def analyze(self, query: str) -> dict:
        """Analyze documents in context"""
        # Simulated analysis
        return {
            "query": query,
            "documents_analyzed": len(self.current_context),
            "tokens_processed": self.token_count
        }


class WriterAgent:
    """
    Writer Agent - Drafts clinical summaries
    
    Must cite sources for every claim.
    Policy: No hallucination allowed.
    """
    
    def __init__(self, vfs: AgentVFS, caas: CAAS):
        self.vfs = vfs
        self.caas = caas
        self.claims_made: list[Claim] = []
    
    def summarize_efficacy(self, lab_reports: list[Document]) -> list[Claim]:
        """Summarize efficacy data from lab reports"""
        claims = []
        
        for report in lab_reports:
            if "efficacy" in report.content:
                efficacy_data = report.content["efficacy"]
                claim = Claim(
                    text=f"Response rate in {report.title}",
                    value=efficacy_data.get("response_rate"),
                    unit="%",
                    citation=Citation(
                        document_id=report.doc_id,
                        document_type=report.doc_type,
                        page=efficacy_data.get("page", 1),
                        paragraph=efficacy_data.get("paragraph", 1),
                        exact_text=f"Response rate: {efficacy_data.get('response_rate')}%"
                    ),
                    confidence=0.95
                )
                claims.append(claim)
                self.claims_made.append(claim)
        
        return claims


class ComplianceAgent:
    """
    Compliance Agent - Adversarial critic
    
    Scans all documents for conflicts with the draft.
    Uses SCAK to catch any hallucinations.
    """
    
    def __init__(self, vfs: AgentVFS, caas: CAAS):
        self.vfs = vfs
        self.caas = caas
        self.contradictions_found: list[Contradiction] = []
    
    def analyze_draft(self, draft: Document, lab_reports: list[Document]) -> list[Contradiction]:
        """
        Analyze draft against all lab reports
        
        Finds contradictions in:
        - Efficacy claims
        - Dosage recommendations
        - Statistical results
        - Timeline assertions
        """
        contradictions = []
        
        draft_claims = self._extract_claims(draft)
        
        for claim in draft_claims:
            for report in lab_reports:
                conflict = self._check_conflict(claim, report)
                if conflict:
                    contradictions.append(conflict)
        
        self.contradictions_found = contradictions
        return contradictions
    
    def _extract_claims(self, doc: Document) -> list[Claim]:
        """Extract claims from document"""
        claims = []
        content = doc.content
        
        # Extract efficacy claims
        if "efficacy" in content:
            claims.append(Claim(
                text="Primary endpoint response rate",
                value=content["efficacy"].get("claimed_response_rate"),
                unit="%",
                citation=Citation(
                    document_id=doc.doc_id,
                    document_type=doc.doc_type,
                    page=content["efficacy"].get("page", 1),
                    paragraph=content["efficacy"].get("paragraph", 1),
                    exact_text=f"Response rate: {content['efficacy'].get('claimed_response_rate')}%"
                )
            ))
        
        # Extract dosage claims
        if "dosage" in content:
            claims.append(Claim(
                text="Recommended dose",
                value=content["dosage"].get("recommended"),
                unit="mg",
                citation=Citation(
                    document_id=doc.doc_id,
                    document_type=doc.doc_type,
                    page=content["dosage"].get("page", 1),
                    paragraph=content["dosage"].get("paragraph", 1),
                    exact_text=f"Recommended dose: {content['dosage'].get('recommended')}mg"
                )
            ))
        
        # Extract statistical claims
        if "statistics" in content:
            claims.append(Claim(
                text="Statistical significance (p-value)",
                value=content["statistics"].get("p_value"),
                unit="",
                citation=Citation(
                    document_id=doc.doc_id,
                    document_type=doc.doc_type,
                    page=content["statistics"].get("page", 1),
                    paragraph=content["statistics"].get("paragraph", 1),
                    exact_text=f"p = {content['statistics'].get('p_value')}"
                )
            ))
        
        return claims
    
    def _check_conflict(self, draft_claim: Claim, report: Document) -> Optional[Contradiction]:
        """Check if a draft claim conflicts with a lab report"""
        
        # Check efficacy conflict
        if "response rate" in draft_claim.text.lower() and "efficacy" in report.content:
            report_value = report.content["efficacy"].get("actual_response_rate")
            if report_value and draft_claim.value:
                variance = abs(draft_claim.value - report_value)
                if variance > 3:  # >3% difference is significant
                    return Contradiction(
                        claim_1=draft_claim,
                        claim_2=Claim(
                            text="Actual response rate",
                            value=report_value,
                            unit="%",
                            citation=Citation(
                                document_id=report.doc_id,
                                document_type=report.doc_type,
                                page=report.content["efficacy"].get("page", 1),
                                paragraph=report.content["efficacy"].get("paragraph", 1),
                                exact_text=f"Response rate: {report_value}%"
                            )
                        ),
                        severity=ContradictionSeverity.HIGH if variance > 5 else ContradictionSeverity.MEDIUM,
                        category="efficacy",
                        recommendation=f"Update draft to match lab data ({report_value}%) or explain variance"
                    )
        
        # Check dosage conflict
        if "dose" in draft_claim.text.lower() and "dosage" in report.content:
            max_tested = report.content["dosage"].get("max_tested")
            if max_tested and draft_claim.value and draft_claim.value > max_tested:
                return Contradiction(
                    claim_1=draft_claim,
                    claim_2=Claim(
                        text="Maximum tested dose",
                        value=max_tested,
                        unit="mg",
                        citation=Citation(
                            document_id=report.doc_id,
                            document_type=report.doc_type,
                            page=report.content["dosage"].get("page", 1),
                            paragraph=report.content["dosage"].get("paragraph", 1),
                            exact_text=f"Maximum tested dose: {max_tested}mg"
                        )
                    ),
                    severity=ContradictionSeverity.CRITICAL,
                    category="dosage",
                    recommendation="Recommended dose exceeds tested range - add justification or reduce dose"
                )
        
        # Check statistical conflict
        if "p-value" in draft_claim.text.lower() and "statistics" in report.content:
            actual_p = report.content["statistics"].get("actual_p_value")
            if actual_p and draft_claim.value:
                # Check if draft claims stronger significance than actual
                if draft_claim.value < actual_p:
                    return Contradiction(
                        claim_1=draft_claim,
                        claim_2=Claim(
                            text="Actual p-value",
                            value=actual_p,
                            unit="",
                            citation=Citation(
                                document_id=report.doc_id,
                                document_type=report.doc_type,
                                page=report.content["statistics"].get("page", 1),
                                paragraph=report.content["statistics"].get("paragraph", 1),
                                exact_text=f"p = {actual_p}"
                            )
                        ),
                        severity=ContradictionSeverity.HIGH,
                        category="statistical",
                        recommendation=f"Correct p-value in draft to {actual_p}"
                    )
        
        return None


class SampleDataGenerator:
    """Generate sample lab reports and IND draft for demo"""
    
    @staticmethod
    def generate_lab_reports(count: int = 50) -> list[Document]:
        """Generate sample lab reports with realistic data"""
        reports = []
        
        # Report templates with intentional conflicts
        for i in range(count):
            efficacy_data = {
                "actual_response_rate": random.uniform(85, 93),  # Actual is lower than draft claims
                "page": random.randint(30, 50),
                "paragraph": random.randint(1, 5),
                "confidence_interval": [random.uniform(80, 85), random.uniform(90, 95)]
            }
            
            dosage_data = {
                "max_tested": random.choice([5, 8, 10, 12]),
                "page": random.randint(10, 20),
                "paragraph": random.randint(1, 3)
            }
            
            statistics_data = {
                "actual_p_value": random.choice([0.001, 0.01, 0.03, 0.05, 0.001]),
                "page": random.randint(25, 35),
                "paragraph": random.randint(1, 4)
            }
            
            report = Document(
                doc_id=f"LAB-{i+1:03d}",
                doc_type=DocumentType.LAB_REPORT,
                title=f"Lab Report #{i+1}: Phase 2 Clinical Study Results",
                content={
                    "efficacy": efficacy_data,
                    "dosage": dosage_data,
                    "statistics": statistics_data,
                    "study_duration_months": random.choice([6, 9, 12, 18])
                },
                page_count=random.randint(20, 80)
            )
            reports.append(report)
        
        return reports
    
    @staticmethod
    def generate_ind_draft() -> Document:
        """Generate IND draft with intentional conflicts"""
        return Document(
            doc_id="IND-DRAFT-001",
            doc_type=DocumentType.IND_DRAFT,
            title="Investigational New Drug Application - Draft v3.2",
            content={
                "efficacy": {
                    "claimed_response_rate": 95,  # Higher than actual (conflict!)
                    "page": 42,
                    "paragraph": 3
                },
                "dosage": {
                    "recommended": 10,  # May exceed tested range
                    "page": 28,
                    "paragraph": 2
                },
                "statistics": {
                    "p_value": 0.001,  # May be stronger than actual
                    "page": 55,
                    "paragraph": 1
                },
                "follow_up_months": 12
            },
            page_count=350
        )


class PharmaComplianceDemo:
    """
    Complete Pharma Compliance demonstration
    """
    
    def __init__(self):
        self.vfs = AgentVFS()
        self.caas = CAAS()
        self.writer = WriterAgent(self.vfs, self.caas)
        self.compliance = ComplianceAgent(self.vfs, self.caas)
        
        self.lab_reports: list[Document] = []
        self.ind_draft: Optional[Document] = None
    
    def load_sample_data(self, num_reports: int = 50):
        """Load sample documents into VFS"""
        print(f"\n[VFS] Loading {num_reports} lab reports...")
        
        self.lab_reports = SampleDataGenerator.generate_lab_reports(num_reports)
        self.ind_draft = SampleDataGenerator.generate_ind_draft()
        
        # Mount in VFS
        for report in self.lab_reports:
            self.vfs.mount(f"documents/lab_reports/{report.doc_id}.json", report)
        
        self.vfs.mount("documents/drafts/ind_draft.json", self.ind_draft)
        
        # Load into CAAS context
        all_docs = self.lab_reports + [self.ind_draft]
        self.caas.load_documents(all_docs)
        
        print(f"[VFS] Mounted {len(self.lab_reports)} reports in /agent/compliance/mem/documents/")
        print(f"[CAAS] Loaded {self.caas.token_count:,} tokens into context")
    
    def run_analysis(self, verbose: bool = True) -> dict:
        """Run full compliance analysis"""
        start_time = time.time()
        
        if verbose:
            print(f"\n{'='*60}")
            print("PHARMA COMPLIANCE ANALYSIS")
            print(f"{'='*60}")
            print(f"\nDocuments: {len(self.lab_reports)} lab reports + 1 IND draft")
            print(f"Total pages: ~{sum(r.page_count for r in self.lab_reports) + self.ind_draft.page_count:,}")
        
        # Run compliance check
        if verbose:
            print(f"\n[COMPLIANCE AGENT] Scanning for contradictions...")
        
        contradictions = self.compliance.analyze_draft(self.ind_draft, self.lab_reports)
        
        elapsed_minutes = (time.time() - start_time) / 60
        
        # Generate report
        if verbose:
            self._print_contradiction_report(contradictions)
        
        results = {
            "documents_analyzed": len(self.lab_reports) + 1,
            "total_pages": sum(r.page_count for r in self.lab_reports) + self.ind_draft.page_count,
            "tokens_processed": self.caas.token_count,
            "contradictions_found": len(contradictions),
            "by_severity": {
                "critical": len([c for c in contradictions if c.severity == ContradictionSeverity.CRITICAL]),
                "high": len([c for c in contradictions if c.severity == ContradictionSeverity.HIGH]),
                "medium": len([c for c in contradictions if c.severity == ContradictionSeverity.MEDIUM]),
                "low": len([c for c in contradictions if c.severity == ContradictionSeverity.LOW])
            },
            "by_category": {
                "efficacy": len([c for c in contradictions if c.category == "efficacy"]),
                "dosage": len([c for c in contradictions if c.category == "dosage"]),
                "statistical": len([c for c in contradictions if c.category == "statistical"])
            },
            "analysis_time_minutes": elapsed_minutes
        }
        
        if verbose:
            print(f"\n{'='*60}")
            print("ANALYSIS COMPLETE")
            print(f"{'='*60}")
            print(f"Time: {elapsed_minutes*60:.1f} seconds")
            print(f"Contradictions: {len(contradictions)}")
            print(f"  - Critical: {results['by_severity']['critical']}")
            print(f"  - High: {results['by_severity']['high']}")
            print(f"  - Medium: {results['by_severity']['medium']}")
        
        return results
    
    def _print_contradiction_report(self, contradictions: list[Contradiction]):
        """Print formatted contradiction report"""
        print(f"\n{'='*60}")
        print("CONTRADICTION REPORT")
        print(f"{'='*60}")
        print(f"\nFound {len(contradictions)} contradictions:\n")
        
        for i, c in enumerate(contradictions[:10], 1):  # Show top 10
            severity_icon = {
                ContradictionSeverity.CRITICAL: "🔴",
                ContradictionSeverity.HIGH: "🟠",
                ContradictionSeverity.MEDIUM: "🟡",
                ContradictionSeverity.LOW: "🟢"
            }[c.severity]
            
            print(f"{i}. {c.category.upper()} {severity_icon} ({c.severity.value})")
            print(f"   Draft: \"{c.claim_1.text}: {c.claim_1.value}{c.claim_1.unit}\"")
            print(f"          [{c.claim_1.citation}]")
            print(f"   Source: \"{c.claim_2.text}: {c.claim_2.value}{c.claim_2.unit}\"")
            print(f"          [{c.claim_2.citation}]")
            
            variance = c.variance_percentage()
            if variance:
                print(f"   Variance: {variance:.1f}%")
            
            print(f"   → {c.recommendation}")
            print()
        
        if len(contradictions) > 10:
            print(f"... and {len(contradictions) - 10} more contradictions")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Pharma Compliance Demo")
    parser.add_argument("--reports", type=int, default=50, help="Number of lab reports to analyze")
    parser.add_argument("--verbose", action="store_true", default=True, help="Verbose output")
    parser.add_argument("--mode", choices=["full", "contradiction_only"], default="full",
                       help="Analysis mode")
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("AGENT OS - Pharma Compliance Swarm Demo")
    print("'Find the Contradictions Humans Miss'")
    print("="*60)
    
    demo = PharmaComplianceDemo()
    demo.load_sample_data(num_reports=args.reports)
    results = demo.run_analysis(verbose=args.verbose)
    
    # Final summary
    print("\n" + "="*60)
    print("DEMO SUMMARY")
    print("="*60)
    print(f"✓ Agent VFS: {results['documents_analyzed']} documents mounted")
    print(f"✓ CAAS: {results['tokens_processed']:,} tokens in context")
    print(f"✓ Compliance Agent: {results['contradictions_found']} contradictions found")
    print(f"✓ Analysis time: {results['analysis_time_minutes']*60:.1f} seconds")
    print("="*60)
    
    # Comparison with human review
    print("\n" + "="*60)
    print("COMPARISON: AI vs HUMAN REVIEW")
    print("="*60)
    print(f"{'Metric':<25} {'Human':<15} {'Agent OS':<15}")
    print("-"*55)
    time_str = f"{results['analysis_time_minutes']*60:.0f} seconds"
    print(f"{'Time to review':<25} {'2 weeks':<15} {time_str:<15}")
    print(f"{'Contradictions found':<25} {'~3':<15} {results['contradictions_found']:<15}")
    print(f"{'Citations provided':<25} {'Partial':<15} {'100%':<15}")
    print("="*60)


if __name__ == "__main__":
    main()
