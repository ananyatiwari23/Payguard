"""
FastAPI HTTP Endpoint Integration Tests for AI-Powered Scam Detection Engine.
Tests all public API routes:
- GET /
- GET /api/v1/health
- GET /api/v1/languages
- POST /api/v1/analyze (Clean invoice, Scam invoice, Hindi & Marathi localization)
- POST /api/v1/analyze/batch
- Input validation (missing required fields, negative amount)
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

try:
    from backend.main import app
except ImportError:
    from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_root_endpoint(client):
    """GET / should return service info and endpoint directory."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "AI-Powered Scam Detection Engine"
    assert "endpoints" in data
    assert "/api/v1/analyze" in data["endpoints"]["analyze"]


def test_health_check_endpoint(client):
    """GET /api/v1/health should return HEALTHY and active components."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "components" in data
    assert "risk_scoring_engine" in data["components"]


def test_supported_languages_endpoint(client):
    """GET /api/v1/languages should return en, hi, mr with descriptions."""
    response = client.get("/api/v1/languages")
    assert response.status_code == 200
    data = response.json()
    assert "languages" in data
    codes = [item["code"] for item in data["languages"]]
    assert "en" in codes
    assert "hi" in codes
    assert "mr" in codes


def test_analyze_clean_invoice(client):
    """POST /api/v1/analyze with clean subscription invoice."""
    payload = {
        "invoice_id": "INV-TEST-001",
        "merchant_name": "Netflix Inc.",
        "recipient_name": "Alice Smith",
        "sender_email": "billing@mailer.netflix.com",
        "amount": 19.99,
        "currency": "USD",
        "invoice_description": "Your monthly Standard subscription for Netflix has been renewed successfully.",
        "language": "en"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["invoice_id"] == "INV-TEST-001"
    assert data["risk_score"] <= 30
    assert data["risk_level"] == "LOW"
    assert data["decision"] == "APPROVE"
    assert data["safeguard_invoked"] is False
    assert len(data["recommendations"]) > 0


def test_analyze_scam_invoice(client):
    """POST /api/v1/analyze with high-risk impersonation scam."""
    payload = {
        "invoice_id": "INV-TEST-002",
        "merchant_name": "GeekSquad Support Billing Dept LLC",
        "recipient_name": "PayGuard User",
        "sender_email": "refund-desk994@service-geeksquad-billing.online",
        "amount": 499.99,
        "currency": "USD",
        "invoice_description": (
            "Annual GeekSquad BestBuy Total Tech Support Auto-Renewal Subscription #GS-8829\n\n"
            "URGENT: Your account was auto-debited $499.99 today. If you did NOT authorize this renewal, "
            "call our toll-free cancellation line at +1 (800) 555-0199 within 2 hours or funds cannot be reversed."
        ),
        "language": "en"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 70
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["decision"] in ["REVIEW", "BLOCK"]
    assert len(data["risk_indicators"]) > 0
    assert "explanation" in data
    assert len(data["recommendations"]) >= 2


def test_analyze_multilingual(client):
    """POST /api/v1/analyze with Hindi and Marathi language requests."""
    base_payload = {
        "invoice_id": "INV-HI-TEST",
        "merchant_name": "PayPal Billing Alert",
        "recipient_name": "Rohan Mehra",
        "sender_email": "paypal.support9821@gmail.com",
        "amount": 899.00,
        "currency": "USD",
        "invoice_description": "URGENT unauthorized charge of $899. Call 1-888-234-9011 within 24 hours to cancel.",
        "language": "hi"
    }
    # Hindi test
    res_hi = client.post("/api/v1/analyze", json=base_payload)
    assert res_hi.status_code == 200
    data_hi = res_hi.json()
    assert any(ord(c) >= 0x0900 and ord(c) <= 0x097F for c in data_hi["explanation"])

    # Marathi test
    payload_mr = {**base_payload, "invoice_id": "INV-MR-TEST", "language": "mr"}
    res_mr = client.post("/api/v1/analyze", json=payload_mr)
    assert res_mr.status_code == 200
    data_mr = res_mr.json()
    assert any(ord(c) >= 0x0900 and ord(c) <= 0x097F for c in data_mr["explanation"])


def test_batch_analyze(client):
    """POST /api/v1/analyze/batch processes multiple invoices in sequence."""
    payload = {
        "invoices": [
            {
                "merchant_name": "Netflix Inc.",
                "recipient_name": "User One",
                "sender_email": "billing@mailer.netflix.com",
                "amount": 15.99,
                "currency": "USD",
                "invoice_description": "Monthly subscription renewal.",
                "language": "en"
            },
            {
                "merchant_name": "Best Buy Geek Squad",
                "recipient_name": "User Two",
                "sender_email": "support1098@gmail.com",
                "amount": 799.00,
                "currency": "USD",
                "invoice_description": "URGENT auto-debit pending. Call immediately to cancel.",
                "language": "en"
            }
        ]
    }
    response = client.post("/api/v1/analyze/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_processed"] == 2
    assert len(data["results"]) == 2
    assert data["high_risk_count"] >= 1


def test_analyze_validation_errors(client):
    """POST /api/v1/analyze validates required fields and types."""
    # Missing required merchant_name
    bad_payload = {
        "recipient_name": "Alice",
        "sender_email": "test@test.com",
        "amount": 100.0,
        "invoice_description": "Test"
    }
    res = client.post("/api/v1/analyze", json=bad_payload)
    assert res.status_code == 422

    # Negative amount
    bad_amount = {
        "merchant_name": "Acme",
        "recipient_name": "Alice",
        "sender_email": "test@test.com",
        "amount": -50.0,
        "invoice_description": "Test"
    }
    res2 = client.post("/api/v1/analyze", json=bad_amount)
    assert res2.status_code == 422
