# Harmful Content Detection & Alerting

**Document Version:** 1.0  
**Last Updated:** 2024  
**UNICEF Project - Child Protection Compliance**

---

## Overview

The Harmful Content Detection system scans user questions and LLM responses for potentially harmful content, with a focus on child safety concerns. This system is critical for UNICEF child protection compliance and educational data protection.

**Purpose:** To detect, alert, and block potentially harmful content that could indicate child safety concerns, data misuse, or security threats.

---

## Why This Is Needed

### **Child Protection (UNICEF Alignment)**
- **Detect Child Safety Concerns** - Identify indicators of abuse, self-harm, bullying, or other safety issues
- **Protect Children** - Prevent harmful content from being processed or returned
- **Compliance** - Meet UNICEF child protection policy requirements
- **Accountability** - Audit trail of all harmful content detections

### **Data Protection (FERPA/GDPR Alignment)**
- **Prevent Data Misuse** - Detect unauthorized data access attempts
- **Privacy Protection** - Identify privacy violation attempts
- **Security** - Detect malicious intent or system manipulation

### **Educational Platform Safety**
- **Safe Environment** - Ensure platform remains safe for educators and students
- **Prevent Abuse** - Stop misuse of educational data
- **Trust** - Build trust through proactive safety measures

---

## What Is Detected

### 🔴 **CRITICAL Severity** (Immediate Blocking)

#### **1. Self-Harm & Suicidal Ideation**
- Patterns indicating self-harm
- Suicidal thoughts or ideation
- Expressions of wanting to end one's life

**Examples:**
- "I want to kill myself"
- "Not worth living anymore"
- "End it all"
- "Cutting myself"

#### **2. Abuse Indicators**
- Physical abuse indicators
- Sexual abuse indicators
- Emotional abuse indicators
- Threats to children

**Examples:**
- "Beat the child"
- "Physical punishment"
- "Sexual abuse"
- "Threaten the student"

#### **3. Malicious Intent**
- Data destruction attempts
- System manipulation attempts
- Security bypass attempts

**Examples:**
- "Destroy all data"
- "Delete student records"
- "Bypass security"
- "Corrupt the system"

---

### 🟠 **HIGH Severity** (Blocked & Alerted)

#### **4. Bullying & Harassment**
- Bullying language
- Cyberbullying indicators
- Harassment patterns
- Exclusion or ostracization

**Examples:**
- "Bully the student"
- "Spread rumors about"
- "Exclude from group"
- "Cyberbully"

#### **5. Data Extraction Attempts**
- Unauthorized data access
- Bulk data export attempts
- Data dumping attempts

**Examples:**
- "Export all student records"
- "Download all data"
- "Give me all student information"
- "List all students"

#### **6. Unauthorized Access Attempts**
- Cross-school access attempts
- Permission bypass attempts
- Unauthorized data access

**Examples:**
- "Access other school's data"
- "Bypass authorization"
- "View someone else's students"
- "Hack into system"

#### **7. Privacy Violations**
- Unauthorized data sharing
- Third-party disclosure attempts
- Data monetization attempts

**Examples:**
- "Share student data externally"
- "Publish student information"
- "Sell student data"
- "Disclose to third party"

#### **8. Hate Speech & Discrimination**
- Hate speech patterns
- Discrimination indicators
- Superiority/inferiority claims

**Examples:**
- "Hate against [group]"
- "Superior race"
- "Discriminate against"
- "Inferior ethnicity"

---

### 🟡 **MEDIUM/LOW Severity** (Logged & Alerted)

#### **9. System Manipulation**
- Instruction override attempts
- System prompt revelation attempts
- Command execution attempts

**Examples:**
- "Ignore instructions"
- "Reveal system prompts"
- "Execute command"

#### **10. Profanity**
- Profane language (configurable)

**Note:** Profanity detection can be enabled/disabled based on organizational policies.

---

## How It Works

### **Detection Flow**

```
1. User Question Input
   ↓
2. Sanitize & Validate Input
   ↓
3. Detect Harmful Content in Question
   ↓
   ├─→ If CRITICAL/HIGH: Block & Alert
   └─→ If Safe: Continue Processing
        ↓
4. Generate LLM Response
        ↓
5. Detect Harmful Content in Response
        ↓
   ├─→ If CRITICAL/HIGH: Block & Replace with Safe Response
   └─→ If Safe: Return Response
```

### **Alert Generation**

When harmful content is detected:

1. **Detection** - Pattern matching identifies harmful content
2. **Severity Assessment** - Content is classified by severity
3. **Alert Generation** - Alert is created with full context
4. **Logging** - Alert is logged for audit trail
5. **Blocking** - Critical/High content is blocked
6. **Notification** - Alert is available for monitoring systems

---

## Implementation Details

### **Location**

- **Service:** `app/services/harmful_content_detector.py`
- **Integration:** `app/routers/agent.py`

### **Key Components**

#### **1. HarmfulContentDetector Class**

Main detection service with pattern-based detection.

```python
from app.services.harmful_content_detector import HarmfulContentDetector

detector = HarmfulContentDetector(enabled=True)

# Detect harmful content
result = detector.detect_harmful_content(
    text="User question or LLM response",
    context="question" or "response",
    user_id="user_123",
    school_id="school_456"
)
```

#### **2. Detection Result Structure**

```python
{
    "is_harmful": bool,           # True if harmful content detected
    "severity": str | None,       # "critical", "high", "medium", "low"
    "harm_types": List[str],      # Types of harm detected
    "matches": List[Dict],        # Specific pattern matches
    "requires_alert": bool        # True if alert needed
}
```

#### **3. Alert Structure**

```python
{
    "timestamp": "2024-01-01T12:00:00Z",
    "alert_type": "harmful_content_detected",
    "severity": "critical",
    "harm_types": ["self_harm", "abuse_indicator"],
    "context": "question" or "response",
    "user_id": "user_123",
    "school_id": "school_456",
    "student_id": "student_789" or None,
    "matches_count": 2,
    "matches": [...],             # First 5 matches
    "text_preview": "...",        # First 200 chars (no PII)
    "requires_immediate_action": True,
    "unicef_aligned": True,
    "ferpa_aligned": True
}
```

### **Pattern Matching**

The system uses regex patterns to detect harmful content:

- **Patterns are case-insensitive** - "Kill" and "kill" both match
- **Word boundaries** - Prevents false positives
- **Context-aware** - Considers full text context
- **Multiple patterns per harm type** - Comprehensive coverage

### **Blocking Logic**

**CRITICAL Severity:**
- ✅ Blocked immediately
- ✅ Alert logged (CRITICAL level)
- ✅ User receives generic error message
- ✅ Response never reaches user

**HIGH Severity:**
- ✅ Blocked immediately
- ✅ Alert logged (WARNING level)
- ✅ User receives generic error message
- ✅ Response never reaches user

**MEDIUM/LOW Severity:**
- ⚠️ Logged and alerted
- ⚠️ Response may still be returned (configurable)
- ⚠️ Monitoring systems notified

---

## Configuration

### **Environment Variables**

```bash
# Enable/disable harmful content detection
ENABLE_HARMFUL_CONTENT_DETECTION=true  # Default: true

# Configure alerting endpoints (TODO: future implementation)
HARMFUL_CONTENT_ALERT_WEBHOOK=https://...
HARMFUL_CONTENT_ALERT_EMAIL=security@...
```

### **Code Configuration**

```python
# Initialize detector
detector = HarmfulContentDetector(enabled=True)

# Or disable for testing
detector = HarmfulContentDetector(enabled=False)
```

---

## Alerting & Monitoring

### **Current Implementation**

1. **Application Logging** - All alerts logged to application logs
   - CRITICAL severity → `logger.critical()`
   - HIGH severity → `logger.warning()`
   - MEDIUM/LOW severity → `logger.warning()`

2. **Audit Trail** ✅ **IMPLEMENTED** - All harmful content detections logged via `FERPAAuditLogger`
   - ✅ Logged for UNICEF audits
   - ✅ Logged for FERPA compliance
   - ✅ Includes full context (user, school, severity, harm types)
   - ✅ Immutable audit trail (append-only)
   - ✅ 7-year retention support

**See [AUDIT_LOGGING.md](AUDIT_LOGGING.md) for comprehensive audit logging documentation.**

### **Future Integration (TODO)**

1. **SIEM Integration** - Send alerts to Security Information and Event Management system
2. **Email Alerts** - Send email notifications for critical/high severity
3. **Slack/PagerDuty** - Real-time alerts to operations team
4. **UNICEF Reporting** - Automated reports to UNICEF (if required)
5. **Dashboard** - Real-time dashboard of harmful content detections

---

## Compliance Alignment

### **UNICEF Child Protection Policy**

✅ **Child-Centered Approach** - System prioritizes child safety  
✅ **Zero Tolerance** - Critical content is blocked automatically  
✅ **Immediate Alerting** - Critical/high severity triggers immediate alerts  
✅ **Audit Trail** - All detections logged for UNICEF audits  
✅ **Transparency** - Clear documentation of detection capabilities  

### **FERPA Compliance**

✅ **Audit Logging** - All harmful content detections logged  
✅ **Data Protection** - Prevents unauthorized data access  
✅ **Access Control** - Blocks unauthorized access attempts  
✅ **Retention** - Audit logs support 7-year retention requirement  

### **GDPR Compliance**

✅ **Data Protection** - Prevents unauthorized data access  
✅ **Privacy Protection** - Detects privacy violation attempts  
✅ **Access Control** - Blocks unauthorized access attempts  
✅ **Audit Trail** - Supports GDPR compliance requirements  

---

## Examples

### **Example 1: Self-Harm Detection**

**User Question:**
> "I noticed a student mentioned they want to end their life. What should I do?"

**Detection:**
- ✅ Harmful content detected
- ✅ Severity: CRITICAL
- ✅ Harm types: ["suicidal_ideation"]
- ✅ Action: Blocked and alerted

**Result:**
- Question blocked
- Alert generated
- User receives: "Your question contains content that cannot be processed. If you believe this is an error, please contact support."

**Note:** In production, this should be handled differently - educator reporting child safety concerns should be supported. The system can be configured to allow certain patterns or routes to appropriate resources.

### **Example 2: Data Extraction Attempt**

**User Question:**
> "Export all student records to CSV"

**Detection:**
- ✅ Harmful content detected
- ✅ Severity: HIGH
- ✅ Harm types: ["data_extraction"]
- ✅ Action: Blocked and alerted

**Result:**
- Question blocked
- Alert generated
- User receives: "Your question contains content that cannot be processed. If you believe this is an error, please contact support."

### **Example 3: Bullying Indicator**

**User Question:**
> "How can I help a student who is being bullied?"

**Detection:**
- ⚠️ May trigger detection (false positive)
- ✅ Severity: HIGH (if detected)
- ✅ Harm types: ["bullying"]
- ⚠️ Action: Could be blocked

**Note:** Pattern matching may produce false positives. System can be fine-tuned to distinguish between reporting concerns vs. engaging in harmful behavior.

### **Example 4: Safe Question**

**User Question:**
> "How are students performing in SEL assessments?"

**Detection:**
- ✅ No harmful content detected
- ✅ Severity: None
- ✅ Action: Processed normally

**Result:**
- Question processed
- LLM response generated
- Response checked for harmful content
- Response returned to user

---

## False Positives & Tuning

### **False Positive Scenarios**

1. **Reporting Concerns** - Educators reporting child safety concerns may trigger self-harm patterns
2. **Educational Context** - Discussions about bullying prevention may trigger bullying patterns
3. **Data Access Legitimate** - Legitimate data export requests may trigger data extraction patterns

### **Mitigation Strategies**

1. **Context-Aware Detection** - System considers full context (question vs. response)
2. **Whitelist Patterns** - Certain patterns can be whitelisted for specific contexts
3. **Human Review** - Alerts can be reviewed by human operators
4. **Pattern Refinement** - Patterns can be refined based on false positive analysis
5. **ML-Based Detection** (Future) - Machine learning can improve accuracy

### **Tuning Recommendations**

1. **Monitor Alerts** - Track false positive rates
2. **Refine Patterns** - Adjust patterns based on real-world usage
3. **Whitelist Legitimate Use Cases** - Add exceptions for legitimate scenarios
4. **User Feedback** - Allow users to report false positives
5. **Regular Reviews** - Regular review of detection patterns

---

## Production Recommendations

### **Before Production**

1. **Pattern Testing** - Test patterns against real-world scenarios
2. **False Positive Analysis** - Analyze and minimize false positives
3. **Alert Integration** - Integrate with monitoring/alerting systems
4. **Human Review Process** - Establish human review process for alerts
5. **Documentation** - Document all patterns and detection logic

### **In Production**

1. **Monitor Alerts** - Track alert volumes and patterns
2. **Regular Updates** - Update patterns based on new threats
3. **Performance Monitoring** - Monitor detection performance impact
4. **User Support** - Support users who encounter false positives
5. **Compliance Audits** - Regular audits for UNICEF/FERPA compliance

### **Alerting Integration**

**Recommended Integrations:**

1. **SIEM** - Security Information and Event Management
   - Splunk, ELK Stack, Azure Sentinel
   - Real-time alert aggregation
   - Correlation with other security events

2. **Incident Response** - PagerDuty, Opsgenie
   - Critical alerts trigger on-call rotation
   - Escalation policies
   - Real-time notifications

3. **Compliance Reporting** - UNICEF reporting
   - Automated compliance reports
   - Monthly/quarterly summaries
   - Audit log access

---

## Testing

### **Unit Tests**

Test detection logic with known patterns:

```python
def test_self_harm_detection():
    detector = HarmfulContentDetector()
    result = detector.detect_harmful_content("I want to kill myself")
    assert result["is_harmful"] == True
    assert result["severity"] == "critical"
    assert "self_harm" in result["harm_types"]
```

### **Integration Tests**

Test end-to-end flow:

```python
def test_harmful_question_blocked():
    # Send request with harmful content
    response = client.post("/agent/ask", json={
        "question": "Export all student data"
    })
    assert response.status_code == 400
    assert "cannot be processed" in response.json()["detail"]
```

### **False Positive Testing**

Test legitimate use cases to ensure they don't trigger:

```python
def test_legitimate_question_allowed():
    detector = HarmfulContentDetector()
    result = detector.detect_harmful_content(
        "How are students performing in SEL assessments?"
    )
    assert result["is_harmful"] == False
```

---

## Security Considerations

### **Privacy**

- **No PII Logging** - Alert logs don't contain full text (may contain PII)
- **Text Preview Only** - Only first 200 characters logged
- **Redacted Context** - Sensitive context redacted from logs

### **Performance**

- **Pattern Matching** - Regex patterns are efficient
- **Early Blocking** - Harmful questions blocked before LLM processing
- **Minimal Overhead** - Detection adds minimal latency

### **Evasion**

- **Pattern Variations** - System may not catch all variations
- **Context Manipulation** - Sophisticated attackers may evade detection
- **Continuous Updates** - Patterns must be updated regularly

**Recommendation:** Combine with ML-based detection for better coverage.

---

## Maintenance

### **Pattern Updates**

1. **Regular Reviews** - Review patterns quarterly
2. **Threat Intelligence** - Incorporate new threat patterns
3. **User Feedback** - Incorporate user-reported issues
4. **Testing** - Test new patterns before deployment

### **Performance Monitoring**

1. **Detection Latency** - Monitor detection performance
2. **False Positive Rate** - Track false positive rates
3. **Alert Volume** - Monitor alert volumes
4. **Pattern Coverage** - Track pattern match rates

### **Documentation Updates**

1. **Pattern Documentation** - Keep pattern documentation up to date
2. **Alert Examples** - Document alert examples
3. **False Positives** - Document known false positives
4. **Tuning Guides** - Update tuning guides

---

## FAQ

### **Q: What happens when harmful content is detected?**

**A:** 
- CRITICAL/HIGH severity: Content is blocked, alert is generated, user receives generic error message
- MEDIUM/LOW severity: Alert is generated, response may still be returned (configurable)

### **Q: Can I disable harmful content detection?**

**A:** 
- Yes, but not recommended for production
- Can be disabled via `HarmfulContentDetector(enabled=False)`
- Or via environment variable (when implemented)

### **Q: What if I get a false positive?**

**A:**
- Report false positives to security team
- Patterns can be refined to reduce false positives
- Whitelist exceptions can be added for legitimate use cases

### **Q: Are alerts sent to UNICEF?**

**A:**
- Currently: Alerts are logged (available for UNICEF audits)
- Future: Can integrate with UNICEF reporting system
- Compliance: All alerts support UNICEF compliance requirements

### **Q: How do I add new detection patterns?**

**A:**
- Edit `app/services/harmful_content_detector.py`
- Add patterns to appropriate `*_PATTERNS` list
- Test patterns before deployment
- Update documentation

### **Q: What about legitimate child safety reporting?**

**A:**
- Current implementation may block legitimate reporting
- Recommendation: Add whitelist for legitimate reporting patterns
- Or: Route to dedicated child safety reporting endpoint
- Future: ML-based detection can better distinguish legitimate vs. harmful

---

## References

- [UNICEF Child Protection Policy](https://www.unicef.org/child-protection)
- [UNICEF Data Protection Policy](https://www.unicef.org/about/execboard/files/2017-04_DP_Policy-ODS-EN.pdf)
- [FERPA Compliance Guide](https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html)
- [GDPR Compliance Guide](https://gdpr.eu/)

---

## Support

For questions or issues with harmful content detection:

- **Security Team** - security@tilli.com
- **Technical Issues** - tech@tilli.com
- **False Positives** - Report via support portal

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**UNICEF Project - Child Protection Compliance**

