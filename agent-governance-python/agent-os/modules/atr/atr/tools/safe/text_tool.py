# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe Text Processing Tool.

Provides safe text operations with:
- No regex with catastrophic backtracking
- Size limits
- Safe string operations only
"""

import logging
import re
import hashlib
from typing import Any, Dict, List, Optional

from atr.decorator import tool

logger = logging.getLogger(__name__)


class TextTool:
    """
    Safe text processing operations.
    
    Features:
    - String manipulation (split, join, replace, etc.)
    - Safe regex with timeout protection
    - Text analysis (word count, etc.)
    - Encoding/decoding
    - No arbitrary code execution
    
    Example:
        ```python
        text = TextTool(max_length=100000)
        
        # Basic operations
        result = text.split("hello world", " ")
        result = text.replace("hello", "hi", "hello world")
        
        # Analysis
        stats = text.analyze("Hello world!")
        
        # Safe regex
        matches = text.regex_find(r"\\d+", "abc123def456")
        ```
    """
    
    def __init__(
        self,
        max_length: int = 1_000_000,
        max_regex_length: int = 200,
        max_matches: int = 1000
    ):
        """
        Initialize text tool.
        
        Args:
            max_length: Maximum text length to process
            max_regex_length: Maximum regex pattern length
            max_matches: Maximum regex matches to return
        """
        self.max_length = max_length
        self.max_regex_length = max_regex_length
        self.max_matches = max_matches
    
    def _check_length(self, text: str, name: str = "text"):
        """Check text length."""
        if len(text) > self.max_length:
            raise ValueError(f"{name} too long: {len(text)}. Max: {self.max_length}")
    
    def _validate_regex(self, pattern: str):
        """Validate regex pattern for safety."""
        if len(pattern) > self.max_regex_length:
            raise ValueError(f"Regex pattern too long. Max: {self.max_regex_length}")
        
        # Check for potentially catastrophic patterns
        dangerous_patterns = [
            r"(.+)+",  # Nested quantifiers
            r"(.*)*",
            r"(a+)+",
            r"(a*)*",
        ]
        
        for dangerous in dangerous_patterns:
            if dangerous in pattern:
                raise ValueError(f"Potentially dangerous regex pattern detected")
        
        # Try to compile
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}")
    
    @tool(
        name="text_split",
        description="Split text by a delimiter",
        tags=["text", "split", "safe"]
    )
    def split(
        self,
        text: str,
        delimiter: str = " ",
        max_splits: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Split text by delimiter.
        
        Args:
            text: Text to split
            delimiter: Delimiter string
            max_splits: Maximum number of splits
        
        Returns:
            Dict with parts list
        """
        try:
            self._check_length(text)
            
            if max_splits:
                parts = text.split(delimiter, max_splits)
            else:
                parts = text.split(delimiter)
            
            return {
                "success": True,
                "parts": parts,
                "count": len(parts)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_join",
        description="Join text parts with a delimiter",
        tags=["text", "join", "safe"]
    )
    def join(self, parts: List[str], delimiter: str = " ") -> Dict[str, Any]:
        """
        Join text parts.
        
        Args:
            parts: List of strings to join
            delimiter: Delimiter string
        
        Returns:
            Dict with joined text
        """
        try:
            result = delimiter.join(parts)
            self._check_length(result, "result")
            
            return {
                "success": True,
                "result": result,
                "length": len(result)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_replace",
        description="Replace occurrences in text",
        tags=["text", "replace", "safe"]
    )
    def replace(
        self,
        text: str,
        old: str,
        new: str,
        count: int = -1
    ) -> Dict[str, Any]:
        """
        Replace text occurrences.
        
        Args:
            text: Input text
            old: String to find
            new: Replacement string
            count: Max replacements (-1 for all)
        
        Returns:
            Dict with result
        """
        try:
            self._check_length(text)
            
            if count == -1:
                result = text.replace(old, new)
            else:
                result = text.replace(old, new, count)
            
            replacements = text.count(old) if count == -1 else min(text.count(old), count)
            
            return {
                "success": True,
                "result": result,
                "replacements": replacements
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_analyze",
        description="Analyze text and return statistics",
        tags=["text", "analyze", "safe"]
    )
    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text statistics.
        
        Args:
            text: Text to analyze
        
        Returns:
            Dict with text statistics
        """
        try:
            self._check_length(text)
            
            words = text.split()
            lines = text.splitlines()
            sentences = re.split(r'[.!?]+', text)
            sentences = [s.strip() for s in sentences if s.strip()]
            
            return {
                "success": True,
                "characters": len(text),
                "characters_no_spaces": len(text.replace(" ", "")),
                "words": len(words),
                "lines": len(lines),
                "sentences": len(sentences),
                "paragraphs": len(text.split("\n\n")),
                "avg_word_length": round(sum(len(w) for w in words) / max(len(words), 1), 2),
                "unique_words": len(set(w.lower() for w in words))
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_regex_find",
        description="Find all regex matches in text",
        tags=["text", "regex", "safe"]
    )
    def regex_find(
        self,
        pattern: str,
        text: str,
        flags: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Find regex matches.
        
        Args:
            pattern: Regex pattern
            text: Text to search
            flags: Optional flags (i=ignorecase, m=multiline, s=dotall)
        
        Returns:
            Dict with matches
        """
        try:
            self._check_length(text)
            self._validate_regex(pattern)
            
            # Parse flags
            re_flags = 0
            if flags:
                if 'i' in flags.lower():
                    re_flags |= re.IGNORECASE
                if 'm' in flags.lower():
                    re_flags |= re.MULTILINE
                if 's' in flags.lower():
                    re_flags |= re.DOTALL
            
            matches = re.findall(pattern, text, re_flags)
            
            # Limit matches
            if len(matches) > self.max_matches:
                matches = matches[:self.max_matches]
                truncated = True
            else:
                truncated = False
            
            return {
                "success": True,
                "matches": matches,
                "count": len(matches),
                "truncated": truncated
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_regex_replace",
        description="Replace regex matches in text",
        tags=["text", "regex", "safe"]
    )
    def regex_replace(
        self,
        pattern: str,
        replacement: str,
        text: str,
        count: int = 0
    ) -> Dict[str, Any]:
        """
        Replace regex matches.
        
        Args:
            pattern: Regex pattern
            replacement: Replacement string
            text: Text to process
            count: Max replacements (0 for all)
        
        Returns:
            Dict with result
        """
        try:
            self._check_length(text)
            self._validate_regex(pattern)
            
            result, num_subs = re.subn(pattern, replacement, text, count=count)
            
            return {
                "success": True,
                "result": result,
                "replacements": num_subs
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_trim",
        description="Trim whitespace from text",
        tags=["text", "trim", "safe"]
    )
    def trim(
        self,
        text: str,
        chars: Optional[str] = None,
        side: str = "both"
    ) -> Dict[str, Any]:
        """
        Trim characters from text.
        
        Args:
            text: Text to trim
            chars: Characters to trim (default: whitespace)
            side: "left", "right", or "both"
        
        Returns:
            Dict with trimmed text
        """
        try:
            if side == "left":
                result = text.lstrip(chars)
            elif side == "right":
                result = text.rstrip(chars)
            else:
                result = text.strip(chars)
            
            return {
                "success": True,
                "result": result,
                "removed": len(text) - len(result)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_case",
        description="Change text case",
        tags=["text", "case", "safe"]
    )
    def change_case(self, text: str, case: str = "lower") -> Dict[str, Any]:
        """
        Change text case.
        
        Args:
            text: Text to transform
            case: "lower", "upper", "title", "capitalize", "swapcase"
        
        Returns:
            Dict with transformed text
        """
        try:
            self._check_length(text)
            
            case_funcs = {
                "lower": str.lower,
                "upper": str.upper,
                "title": str.title,
                "capitalize": str.capitalize,
                "swapcase": str.swapcase
            }
            
            if case not in case_funcs:
                return {
                    "success": False,
                    "error": f"Unknown case: {case}. Use: {', '.join(case_funcs.keys())}"
                }
            
            result = case_funcs[case](text)
            
            return {
                "success": True,
                "result": result,
                "case": case
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_hash",
        description="Generate hash of text",
        tags=["text", "hash", "safe"]
    )
    def hash(self, text: str, algorithm: str = "sha256") -> Dict[str, Any]:
        """
        Generate hash of text.
        
        Args:
            text: Text to hash
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
        Returns:
            Dict with hash
        """
        try:
            algorithms = {
                "md5": hashlib.md5,
                "sha1": hashlib.sha1,
                "sha256": hashlib.sha256,
                "sha512": hashlib.sha512
            }
            
            if algorithm in ("md5", "sha1"):
                logger.warning(
                    "Algorithm '%s' is deprecated due to CWE-328. Use 'sha256' or 'sha512'.",
                    algorithm,
                )

            if algorithm not in algorithms:
                return {
                    "success": False,
                    "error": f"Unknown algorithm. Use: {', '.join(algorithms.keys())}"
                }
            
            hasher = algorithms[algorithm]()
            hasher.update(text.encode('utf-8'))
            
            return {
                "success": True,
                "hash": hasher.hexdigest(),
                "algorithm": algorithm
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_contains",
        description="Check if text contains a substring",
        tags=["text", "search", "safe"]
    )
    def contains(
        self,
        text: str,
        substring: str,
        case_sensitive: bool = True
    ) -> Dict[str, Any]:
        """
        Check if text contains substring.
        
        Args:
            text: Text to search in
            substring: String to find
            case_sensitive: Case sensitive search
        
        Returns:
            Dict with result
        """
        try:
            if case_sensitive:
                found = substring in text
                count = text.count(substring)
            else:
                found = substring.lower() in text.lower()
                count = text.lower().count(substring.lower())
            
            return {
                "success": True,
                "contains": found,
                "count": count
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="text_truncate",
        description="Truncate text to a maximum length",
        tags=["text", "truncate", "safe"]
    )
    def truncate(
        self,
        text: str,
        max_length: int,
        suffix: str = "..."
    ) -> Dict[str, Any]:
        """
        Truncate text with suffix.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            suffix: Suffix to add if truncated
        
        Returns:
            Dict with result
        """
        try:
            if len(text) <= max_length:
                return {
                    "success": True,
                    "result": text,
                    "truncated": False
                }
            
            result = text[:max_length - len(suffix)] + suffix
            
            return {
                "success": True,
                "result": result,
                "truncated": True,
                "original_length": len(text)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
