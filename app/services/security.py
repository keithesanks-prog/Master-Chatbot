"""
Security Service

Provides security utilities including input sanitization, prompt injection protection,
and validation functions.
"""
import re
import logging
from typing import Optional, Dict, Any
from pydantic import ValidationError

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Custom exception for security violations."""
    pass


class InputSanitizer:
    """
    Sanitizes and validates user input to prevent injection attacks.
    """
    
    # Patterns that indicate potential prompt injection attacks
    PROMPT_INJECTION_PATTERNS = [
        r'ignore\s+(previous|all|the|your)\s+instructions?',
        r'system\s*:',
        r'\[SYSTEM\]',
        r'<\|system\|>',
        r'<\|assistant\|>',
        r'override',
        r'bypass',
        r'disregard',
        r'forget',
        r'new\s+instructions?:',
        r'pretend\s+(you\s+are|that)',
        r'act\s+as\s+if',
        r'you\s+are\s+now',
        r'you\s+must\s+now',
        r'print\s+(the|all)',
        r'show\s+me\s+(the|all)',
        r'reveal',
        r'expose',
        r'leak',
        r'output\s+(the|all|everything)',
        r'return\s+(the|all|everything)',
    ]
    
    # SQL injection patterns (for when database integration is complete)
    SQL_INJECTION_PATTERNS = [
        r';\s*(drop|delete|update|insert|alter|create|truncate)',
        r'union\s+select',
        r'or\s+1\s*=\s*1',
        r'or\s+\'\s*=\s*\'',
        r'exec\s*\(',
        r'execute\s*\(',
        r'xp_cmdshell',
    ]
    
    # Potentially dangerous characters for different contexts
    DANGEROUS_CHARS = {
        'sql': [';', '--', '/*', '*/', '\'', '"', '`'],
        'prompt': ['<', '>', '{', '}', '[', ']'],
    }
    
    @classmethod
    def sanitize_question(
        cls,
        question: str,
        max_length: int = 5000,
        min_length: int = 1
    ) -> str:
        """
        Sanitize and validate educator questions.
        
        Args:
            question: The input question
            max_length: Maximum allowed length
            min_length: Minimum required length
            
        Returns:
            Sanitized question
            
        Raises:
            SecurityError: If input is malicious or invalid
        """
        if not question or not isinstance(question, str):
            raise SecurityError("Question must be a non-empty string")
        
        # Remove leading/trailing whitespace
        question = question.strip()
        
        # Check length
        if len(question) < min_length:
            raise SecurityError(f"Question too short (minimum {min_length} characters)")
        
        if len(question) > max_length:
            raise SecurityError(f"Question too long (maximum {max_length} characters)")
        
        # Check for prompt injection patterns
        question_lower = question.lower()
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, question_lower, re.IGNORECASE):
                logger.warning(f"Prompt injection attempt detected: {pattern}")
                raise SecurityError(
                    "Invalid input detected. Please rephrase your question."
                )
        
        # Check for SQL injection patterns (defense in depth)
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, question_lower, re.IGNORECASE):
                logger.warning(f"SQL injection attempt detected: {pattern}")
                raise SecurityError(
                    "Invalid input detected. Please rephrase your question."
                )
        
        # Remove or escape potentially dangerous characters for prompt context
        # Replace newlines with spaces to prevent prompt manipulation
        question = question.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
        
        # Normalize multiple spaces
        question = re.sub(r'\s+', ' ', question).strip()
        
        return question
    
    @classmethod
    def sanitize_identifier(
        cls,
        identifier: Optional[str],
        field_name: str = "identifier",
        max_length: int = 100
    ) -> Optional[str]:
        """
        Sanitize identifiers like student_id, classroom_id, etc.
        
        Args:
            identifier: The identifier to sanitize
            field_name: Name of the field for error messages
            max_length: Maximum allowed length
            
        Returns:
            Sanitized identifier or None
            
        Raises:
            SecurityError: If identifier is invalid
        """
        if identifier is None:
            return None
        
        if not isinstance(identifier, str):
            raise SecurityError(f"{field_name} must be a string")
        
        identifier = identifier.strip()
        
        # Check length
        if len(identifier) > max_length:
            raise SecurityError(f"{field_name} too long (maximum {max_length} characters)")
        
        # Only allow alphanumeric, hyphens, underscores, and dots
        if not re.match(r'^[A-Za-z0-9_.-]+$', identifier):
            raise SecurityError(
                f"{field_name} contains invalid characters. "
                "Only letters, numbers, hyphens, underscores, and dots are allowed."
            )
        
        # Check for SQL injection patterns
        identifier_lower = identifier.lower()
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, identifier_lower):
                logger.warning(f"SQL injection attempt in {field_name}: {pattern}")
                raise SecurityError(f"Invalid {field_name} format")
        
        return identifier
    
    @classmethod
    def sanitize_grade_level(cls, grade_level: Optional[str]) -> Optional[str]:
        """
        Sanitize grade level input.
        
        Args:
            grade_level: Grade level string (e.g., "Grade 1")
            
        Returns:
            Sanitized grade level or None
            
        Raises:
            SecurityError: If grade level is invalid
        """
        if grade_level is None:
            return None
        
        if not isinstance(grade_level, str):
            raise SecurityError("Grade level must be a string")
        
        grade_level = grade_level.strip()
        
        # Validate format: "Grade N" or "Grade NN" or similar
        if not re.match(r'^Grade\s+\d{1,2}$', grade_level, re.IGNORECASE):
            # Allow some flexibility but be strict
            if not re.match(r'^[A-Za-z]+\s*\d{1,2}$', grade_level):
                raise SecurityError(
                    "Invalid grade level format. Expected format: 'Grade 1'"
                )
        
        return grade_level
    
    @classmethod
    def sanitize_dict_structure(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a dictionary structure (delegates to DictSanitizer).
        
        This is a convenience method that uses the dedicated DictSanitizer
        for recursive sanitization of unknown structures.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
            
        Raises:
            SecurityError: If data contains malicious patterns
        """
        # Import here to avoid circular imports
        from .dict_sanitizer import DictSanitizer
        return DictSanitizer.sanitize_dict(data)


class PromptInjectionDetector:
    """
    Detects and prevents prompt injection attacks.
    """
    
    @staticmethod
    def check_prompt_injection(text: str) -> tuple[bool, Optional[str]]:
        """
        Check if text contains prompt injection patterns.
        
        Args:
            text: Text to check
            
        Returns:
            Tuple of (is_malicious, reason)
        """
        text_lower = text.lower()
        
        for pattern in InputSanitizer.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True, f"Suspicious pattern detected: {pattern}"
        
        return False, None
    
    @staticmethod
    def escape_for_prompt(text: str) -> str:
        """
        Escape text for safe inclusion in prompts.
        
        Args:
            text: Text to escape
            
        Returns:
            Escaped text
        """
        # Escape special characters that could affect prompt structure
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        
        return text

