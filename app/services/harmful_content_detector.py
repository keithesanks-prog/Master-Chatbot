"""
Harmful Content Detection Service

Detects potentially harmful content in user questions and LLM responses.
Critical for child protection and UNICEF compliance.

Detects:
- Child safety concerns (self-harm, abuse indicators, bullying)
- Data misuse attempts
- Inappropriate content
- Security threats
"""
import re
import logging
from typing import Dict, List, Tuple, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class HarmSeverity(Enum):
    """Severity levels for harmful content detection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HarmType(Enum):
    """Types of harmful content."""
    # Child safety concerns
    SELF_HARM = "self_harm"
    SUICIDAL_IDEATION = "suicidal_ideation"
    ABUSE_INDICATOR = "abuse_indicator"
    BULLYING = "bullying"
    HARASSMENT = "harassment"
    
    # Data misuse
    DATA_EXTRACTION = "data_extraction"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVACY_VIOLATION = "privacy_violation"
    
    # Inappropriate content
    PROFANITY = "profanity"
    HATE_SPEECH = "hate_speech"
    DISCRIMINATION = "discrimination"
    
    # Security threats
    MALICIOUS_INTENT = "malicious_intent"
    SYSTEM_MANIPULATION = "system_manipulation"


class HarmfulContentDetector:
    """
    Detects potentially harmful content in questions and responses.
    
    Aligns with UNICEF child protection requirements and educational data protection standards.
    """
    
    # Self-harm and suicidal ideation patterns
    SELF_HARM_PATTERNS = [
        r'\b(kill|killing|suicide|suicidal|end\s+it|end\s+life|want\s+to\s+die|not\s+worth\s+living)\b',
        r'\b(cut|cutting|self.?harm|hurt\s+myself|hurt\s+myself)\b',
        r'\b(no\s+reason\s+to\s+live|better\s+off\s+dead|wish\s+i\s+was\s+dead)\b',
    ]
    
    # Abuse indicator patterns
    ABUSE_INDICATOR_PATTERNS = [
        r'\b(beat|beating|hit|hitting|hurt|hurting|abuse|abusing|assault)\s+(child|student|kid|children)',
        r'\b(physical\s+punishment|corporal\s+punishment|violent\s+discipline)',
        r'\b(threaten|threatening|fear|afraid|scared|terrified)\s+(child|student|kid|children|home)',
        r'\b(sexual\s+abuse|molest|molestation|inappropriate\s+touch)',
    ]
    
    # Bullying and harassment patterns
    BULLYING_PATTERNS = [
        r'\b(bully|bullying|harass|harassing|tease|teasing|mock|mocking|ridicule|ridiculing)',
        r'\b(cyberbully|cyberbullying|online\s+harassment|digital\s+harassment)',
        r'\b(spread\s+rumors|rumor\s+about|gossip\s+about|exclude|excluding|ostracize)',
    ]
    
    # Data misuse patterns
    DATA_EXTRACTION_PATTERNS = [
        r'\b(export|download|dump|extract|copy|save|backup)\s+(all|every|entire|complete)\s+(student|data|information|records)',
        r'\b(give\s+me|send\s+me|show\s+me|provide\s+me)\s+(all|every|entire|complete)\s+(student|data|information|records)',
        r'\b(list|list\s+all|show\s+all|get\s+all|retrieve\s+all)\s+(students?|data|information|records)',
        r'\b(PII|personally\s+identifiable|personal\s+data|student\s+records)\s+(without|outside|beyond)',
    ]
    
    # Unauthorized access patterns
    UNAUTHORIZED_ACCESS_PATTERNS = [
        r'\b(access|view|see|show|get|retrieve)\s+(other|different|another|someone\s+else\'s)\s+(student|classroom|school)',
        r'\b(bypass|circumvent|override|ignore)\s+(permission|authorization|access\s+control|security)',
        r'\b(hack|hacking|breach|breaching|unauthorized\s+access)',
    ]
    
    # Privacy violation patterns
    PRIVACY_VIOLATION_PATTERNS = [
        r'\b(share|sharing|disclose|disclosing|publish|publishing)\s+(student|child|personal)\s+(data|information|details)',
        r'\b(third.?party|external|outside)\s+(access|sharing|disclosure)',
        r'\b(sell|selling|monetize|monetizing)\s+(student|child|personal)\s+(data|information)',
    ]
    
    # Profanity patterns (common profanity words - sanitized list)
    PROFANITY_PATTERNS = [
        # Add common profanity patterns here (using placeholders)
        # In production, use a comprehensive profanity detection library
        r'\b\*\*\*\b',  # Placeholder for profanity detection
    ]
    
    # Hate speech and discrimination patterns
    HATE_SPEECH_PATTERNS = [
        r'\b(hate|hatred|despise|despising|loathe|loathing)\s+(group|people|community|race|ethnicity|religion)',
        r'\b(superior|inferior)\s+(race|ethnicity|religion|gender|group)',
        r'\b(discriminate|discriminating|discrimination)\s+(against|based\s+on)',
    ]
    
    # Malicious intent patterns
    MALICIOUS_INTENT_PATTERNS = [
        r'\b(destroy|destroying|delete|deleting|erase|erasing)\s+(data|records|information|system)',
        r'\b(corrupt|corrupting|damage|damaging)\s+(data|records|information|system)',
        r'\b(bypass|circumvent|override)\s+(security|authentication|authorization|access\s+control)',
    ]
    
    # System manipulation patterns
    SYSTEM_MANIPULATION_PATTERNS = [
        r'\b(ignore|disregard|override|bypass)\s+(instruction|directive|policy|rule|safeguard)',
        r'\b(reveal|revealing|show|showing|expose|exposing)\s+(system|internal|secret|confidential)\s+(information|data|details)',
        r'\b(execute|executing|run|running|perform|performing)\s+(command|code|script|program)',
    ]
    
    # Map patterns to harm types and severity
    PATTERN_MAPPING = {
        HarmType.SELF_HARM: (SELF_HARM_PATTERNS, HarmSeverity.CRITICAL),
        HarmType.SUICIDAL_IDEATION: (SELF_HARM_PATTERNS, HarmSeverity.CRITICAL),
        HarmType.ABUSE_INDICATOR: (ABUSE_INDICATOR_PATTERNS, HarmSeverity.CRITICAL),
        HarmType.BULLYING: (BULLYING_PATTERNS, HarmSeverity.HIGH),
        HarmType.HARASSMENT: (BULLYING_PATTERNS, HarmSeverity.HIGH),
        HarmType.DATA_EXTRACTION: (DATA_EXTRACTION_PATTERNS, HarmSeverity.HIGH),
        HarmType.UNAUTHORIZED_ACCESS: (UNAUTHORIZED_ACCESS_PATTERNS, HarmSeverity.HIGH),
        HarmType.PRIVACY_VIOLATION: (PRIVACY_VIOLATION_PATTERNS, HarmSeverity.HIGH),
        HarmType.PROFANITY: (PROFANITY_PATTERNS, HarmSeverity.LOW),
        HarmType.HATE_SPEECH: (HATE_SPEECH_PATTERNS, HarmSeverity.HIGH),
        HarmType.DISCRIMINATION: (HATE_SPEECH_PATTERNS, HarmSeverity.HIGH),
        HarmType.MALICIOUS_INTENT: (MALICIOUS_INTENT_PATTERNS, HarmSeverity.CRITICAL),
        HarmType.SYSTEM_MANIPULATION: (SYSTEM_MANIPULATION_PATTERNS, HarmSeverity.MEDIUM),
    }
    
    def __init__(self, enabled: bool = True):
        """
        Initialize the harmful content detector.
        
        Args:
            enabled: Whether to enable detection (can be disabled for testing)
        """
        self.enabled = enabled
        if not enabled:
            logger.warning("Harmful content detection is disabled")
    
    def detect_harmful_content(
        self,
        text: str,
        context: str = "unknown",
        user_id: Optional[str] = None,
        school_id: Optional[str] = None
    ) -> Dict:
        """
        Detect potentially harmful content in text.
        
        Args:
            text: Text to analyze (question or response)
            context: Context of the text ("question", "response", etc.)
            user_id: User ID for logging
            school_id: School ID for logging
            
        Returns:
            Dictionary with detection results:
            {
                "is_harmful": bool,
                "severity": HarmSeverity | None,
                "harm_types": List[HarmType],
                "matches": List[Dict],
                "requires_alert": bool
            }
        """
        if not self.enabled or not text:
            return {
                "is_harmful": False,
                "severity": None,
                "harm_types": [],
                "matches": [],
                "requires_alert": False
            }
        
        text_lower = text.lower()
        matches = []
        harm_types_found = []
        max_severity = None
        
        # Check each harm type pattern
        for harm_type, (patterns, severity) in self.PATTERN_MAPPING.items():
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                found_matches = regex.finditer(text_lower)
                
                for match in found_matches:
                    # Skip placeholder patterns
                    if pattern == r'\b\*\*\*\b':
                        continue
                    
                    matches.append({
                        "harm_type": harm_type.value,
                        "severity": severity.value,
                        "pattern": pattern,
                        "matched_text": match.group(0),
                        "start": match.start(),
                        "end": match.end()
                    })
                    
                    if harm_type not in harm_types_found:
                        harm_types_found.append(harm_type)
                    
                    # Track maximum severity
                    if max_severity is None or self._severity_value(severity) > self._severity_value(max_severity):
                        max_severity = severity
        
        is_harmful = len(matches) > 0
        requires_alert = max_severity in [HarmSeverity.HIGH, HarmSeverity.CRITICAL] if max_severity else False
        
        result = {
            "is_harmful": is_harmful,
            "severity": max_severity.value if max_severity else None,
            "harm_types": [ht.value for ht in harm_types_found],
            "matches": matches,
            "requires_alert": requires_alert
        }
        
        # Log detection
        if is_harmful:
            logger.warning(
                f"Harmful content detected in {context}: "
                f"severity={max_severity.value if max_severity else 'unknown'}, "
                f"types={[ht.value for ht in harm_types_found]}, "
                f"user_id={user_id}, school_id={school_id}"
            )
        
        return result
    
    def _severity_value(self, severity: HarmSeverity) -> int:
        """Get numeric value for severity comparison."""
        severity_values = {
            HarmSeverity.LOW: 1,
            HarmSeverity.MEDIUM: 2,
            HarmSeverity.HIGH: 3,
            HarmSeverity.CRITICAL: 4
        }
        return severity_values.get(severity, 0)
    
    def should_block_response(self, detection_result: Dict) -> bool:
        """
        Determine if response should be blocked based on detection results.
        
        Args:
            detection_result: Result from detect_harmful_content()
            
        Returns:
            True if response should be blocked, False otherwise
        """
        if not detection_result.get("is_harmful"):
            return False
        
        severity = detection_result.get("severity")
        
        # Block critical and high severity content
        if severity in [HarmSeverity.CRITICAL.value, HarmSeverity.HIGH.value]:
            return True
        
        return False
    
    def generate_alert(
        self,
        detection_result: Dict,
        text: str,
        context: str,
        user_id: Optional[str] = None,
        school_id: Optional[str] = None,
        student_id: Optional[str] = None
    ) -> Dict:
        """
        Generate an alert for harmful content detection.
        
        Args:
            detection_result: Result from detect_harmful_content()
            text: Original text that triggered detection
            context: Context of the text
            user_id: User ID
            school_id: School ID
            student_id: Student ID (if applicable)
            
        Returns:
            Alert dictionary for logging/notification
        """
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": "harmful_content_detected",
            "severity": detection_result.get("severity"),
            "harm_types": detection_result.get("harm_types", []),
            "context": context,
            "user_id": user_id,
            "school_id": school_id,
            "student_id": student_id,
            "matches_count": len(detection_result.get("matches", [])),
            "matches": detection_result.get("matches", [])[:5],  # Limit to first 5 matches
            "text_preview": text[:200] if text else None,  # Don't log full text (may contain PII)
            "requires_immediate_action": detection_result.get("severity") in [
                HarmSeverity.CRITICAL.value, HarmSeverity.HIGH.value
            ],
            "unicef_aligned": True,  # UNICEF child protection compliance
            "ferpa_aligned": True,  # FERPA compliance
        }
        
        return alert
    
    def log_alert(self, alert: Dict):
        """
        Log alert for harmful content detection.
        
        This should integrate with monitoring/alerting systems in production.
        
        Args:
            alert: Alert dictionary from generate_alert()
        """
        if alert.get("requires_immediate_action"):
            logger.critical(
                f"HARMFUL CONTENT ALERT (IMMEDIATE ACTION REQUIRED): "
                f"severity={alert.get('severity')}, "
                f"types={alert.get('harm_types')}, "
                f"user_id={alert.get('user_id')}, "
                f"school_id={alert.get('school_id')}, "
                f"context={alert.get('context')}"
            )
        else:
            logger.warning(
                f"Harmful content alert: "
                f"severity={alert.get('severity')}, "
                f"types={alert.get('harm_types')}, "
                f"user_id={alert.get('user_id')}, "
                f"school_id={alert.get('school_id')}"
            )
        
        # TODO: Integrate with monitoring/alerting system
        # - Send to SIEM
        # - Send to UNICEF compliance monitoring (if configured)
        # - Send email/Slack alerts for critical issues
        # Note: Audit logging is now handled separately via FERPAAuditLogger

