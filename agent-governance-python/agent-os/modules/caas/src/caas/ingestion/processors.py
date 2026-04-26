# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Data ingestion module for processing different file formats.
"""

import re
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from io import BytesIO

from caas.models import Document, ContentFormat, DocumentType, Section


class BaseProcessor(ABC):
    """Base class for document processors."""
    
    @abstractmethod
    def process(self, content: bytes, metadata: Dict[str, Any]) -> Document:
        """Process raw content into a Document."""
        pass
    
    def _extract_sections(self, text: str) -> List[Section]:
        """Extract sections from text based on common patterns."""
        sections = []
        
        # Pattern for headers (markdown-style or numbered)
        header_pattern = r'(?:^|\n)(#{1,6}\s+.+|[A-Z][^\n]{5,80}:|\d+\.\s+[A-Z][^\n]+)'
        matches = list(re.finditer(header_pattern, text))
        
        if not matches:
            # No clear sections, treat as single section
            return [Section(
                title="Main Content",
                content=text,
                start_pos=0,
                end_pos=len(text)
            )]
        
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            title = match.group(1).strip('#: ')
            content = text[start:end].strip()
            
            sections.append(Section(
                title=title,
                content=content,
                start_pos=start,
                end_pos=end
            ))
        
        return sections


class PDFProcessor(BaseProcessor):
    """Processor for PDF documents."""
    
    def process(self, content: bytes, metadata: Dict[str, Any]) -> Document:
        """Process PDF content."""
        try:
            from pypdf import PdfReader
        except ImportError:
            raise ImportError("pypdf is required for PDF processing")
        
        pdf_file = BytesIO(content)
        reader = PdfReader(pdf_file)
        
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"
        
        sections = self._extract_sections(text)
        
        return Document(
            id=metadata.get("id", ""),
            title=metadata.get("title", "Untitled PDF"),
            content=text,
            format=ContentFormat.PDF,
            detected_type=DocumentType.UNKNOWN,
            sections=sections,
            metadata=metadata
        )


class HTMLProcessor(BaseProcessor):
    """Processor for HTML documents."""
    
    def process(self, content: bytes, metadata: Dict[str, Any]) -> Document:
        """Process HTML content."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            raise ImportError("beautifulsoup4 is required for HTML processing")
        
        soup = BeautifulSoup(content, 'lxml')
        
        # Extract title
        title = soup.title.string if soup.title else "Untitled HTML"
        
        # Remove script and style elements
        for element in soup(['script', 'style', 'nav', 'footer']):
            element.decompose()
        
        # Extract sections based on headers with hierarchy tracking
        sections = []
        current_h1 = None  # Track current chapter (H1)
        current_h2 = None  # Track current parent section (H2)
        
        for header in soup.find_all(['h1', 'h2', 'h3', 'h4']):
            section_title = header.get_text().strip()
            header_level = header.name  # 'h1', 'h2', etc.
            
            # Update hierarchy tracking BEFORE processing content
            if header_level == 'h1':
                current_h1 = section_title
                current_h2 = None
            elif header_level == 'h2':
                current_h2 = section_title
            
            # Get content until next header or end
            content_parts = []
            for sibling in header.find_next_siblings():
                if sibling.name in ['h1', 'h2', 'h3', 'h4']:
                    break
                content_parts.append(sibling.get_text())
            
            section_content = '\n'.join(content_parts).strip()
            if section_content:
                # Assign hierarchy based on current tracking
                chapter = None
                parent_section = None
                
                if header_level == 'h1':
                    # H1 sections don't have chapter/parent
                    pass
                elif header_level == 'h2':
                    chapter = current_h1
                elif header_level in ['h3', 'h4']:
                    chapter = current_h1
                    parent_section = current_h2
                
                sections.append(Section(
                    title=section_title,
                    content=section_content,
                    start_pos=0,
                    end_pos=len(section_content),
                    chapter=chapter,
                    parent_section=parent_section
                ))
        
        # Get all text
        text = soup.get_text(separator='\n', strip=True)
        
        if not sections:
            sections = self._extract_sections(text)
        
        return Document(
            id=metadata.get("id", ""),
            title=title,
            content=text,
            format=ContentFormat.HTML,
            detected_type=DocumentType.UNKNOWN,
            sections=sections,
            metadata=metadata
        )


class CodeProcessor(BaseProcessor):
    """Processor for source code files."""
    
    def process(self, content: bytes, metadata: Dict[str, Any]) -> Document:
        """Process source code content."""
        text = content.decode('utf-8', errors='ignore')
        
        # Detect programming language from metadata or content
        language = metadata.get("language", self._detect_language(text))
        
        # Extract sections (classes, functions, etc.)
        sections = self._extract_code_sections(text, language)
        
        if not sections:
            sections = [Section(
                title="Source Code",
                content=text,
                start_pos=0,
                end_pos=len(text)
            )]
        
        return Document(
            id=metadata.get("id", ""),
            title=metadata.get("title", "Source Code"),
            content=text,
            format=ContentFormat.CODE,
            detected_type=DocumentType.SOURCE_CODE,
            sections=sections,
            metadata={**metadata, "language": language}
        )
    
    def _detect_language(self, text: str) -> str:
        """Simple language detection based on syntax."""
        if 'def ' in text and ':' in text:
            return 'python'
        elif 'function' in text and '{' in text:
            return 'javascript'
        elif 'public class' in text or 'private class' in text:
            return 'java'
        elif '#include' in text:
            return 'c++'
        return 'unknown'
    
    def _extract_code_sections(self, text: str, language: str) -> List[Section]:
        """Extract code sections (functions, classes, etc.)."""
        sections = []
        
        if language == 'python':
            # Match class and function definitions
            pattern = r'(?:^|\n)((?:class|def)\s+\w+[^\n]*:)'
            matches = list(re.finditer(pattern, text, re.MULTILINE))
            
            for i, match in enumerate(matches):
                start = match.start()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                title = match.group(1).strip()
                content = text[start:end].strip()
                
                sections.append(Section(
                    title=title,
                    content=content,
                    start_pos=start,
                    end_pos=end
                ))
        
        return sections


class ProcessorFactory:
    """Factory for creating appropriate processors."""
    
    @staticmethod
    def get_processor(format: ContentFormat) -> BaseProcessor:
        """Get processor for given format."""
        processors = {
            ContentFormat.PDF: PDFProcessor(),
            ContentFormat.HTML: HTMLProcessor(),
            ContentFormat.CODE: CodeProcessor(),
        }
        
        processor = processors.get(format)
        if not processor:
            raise ValueError(f"No processor available for format: {format}")
        
        return processor
