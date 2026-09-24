import pytest
from agentguard.net.models import NetPolicy
from agentguard.net.scanner import Redactor

@pytest.fixture
def policy():
    return NetPolicy()

@pytest.fixture
def redactor(policy):
    return Redactor(policy)

def test_ssn_redaction(redactor):
    text = "My SSN is 123-45-6789 and 345-67-8901"
    redacted, findings = redactor.scan_and_redact(text, "body")
    assert "My SSN is [REDACTED:ssn] and [REDACTED:ssn]" in redacted
    assert len(findings) > 0
    assert findings[0].evidence["count"] == 2

def test_aws_key_redaction(redactor):
    text = "AKIAIOSFODNN7EXAMPLE"
    redacted, findings = redactor.scan_and_redact(text, "body")
    assert redacted == "[REDACTED:aws_access_key]"
    assert findings[0].verdict_hint == "DENY"

def test_email_bulk(redactor):
    text = "test1@example.com test2@example.com test3@example.com test4@example.com test5@example.com"
    redacted, findings = redactor.scan_and_redact(text, "body")
    assert "[REDACTED:email_bulk]" in redacted
    assert findings[0].reason_code == "NET_PII_EGRESS"

def test_high_entropy(redactor):
    # A random 40 char string
    text = "x9Kj3Mn8vBq2Zc5Pw7Yt4Lg1Fd6Hk0RsVbXnNmQcE" 
    redacted, findings = redactor.scan_and_redact(text, "body")
    assert "[REDACTED:high_entropy]" in redacted
    assert findings[0].verdict_hint == "ASK_HUMAN"
