import time
import json
import hmac
import hashlib
import sqlite3
import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Redirect main.DB_NAME to a temporary SQLite database per test."""
    test_db_path = str(tmp_path / "test_analytics.db")
    monkeypatch.setattr(main, "DB_NAME", test_db_path)
    main.init_db()
    return test_db_path


@pytest.fixture
def client(isolated_db):
    return TestClient(main.app)


def sign_stripe_payload(payload_dict: dict, secret: str = None) -> tuple[bytes, str]:
    """Generate a valid Stripe-Signature header matching Stripe's HMAC-SHA256 spec."""
    signing_secret = secret or main.WEBHOOK_SECRET or "whsec_test_secret_123"
    main.WEBHOOK_SECRET = signing_secret
    raw_body = json.dumps(payload_dict).encode("utf-8")
    timestamp = int(time.time())
    signed_payload = f"{timestamp}.".encode("utf-8") + raw_body
    signature = hmac.new(
        signing_secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()
    return raw_body, f"t={timestamp},v1={signature}"


def test_quota_tracking_and_402_blocking(client, isolated_db):
    """Verify free users can log up to 20 events and receive 402 Payment Required at the limit."""
    visitor_id = "usr_test_free_001"

    # 1. Initial quota check shows full 20-event allowance
    res = client.get(f"/api/v1/quota-check/{visitor_id}")
    assert res.status_code == 200
    assert res.json()["remaining"] == 20
    assert res.json()["allowed"] is True

    # 2. Send 20 tracked events
    for i in range(20):
        track_res = client.post(
            "/api/v1/track",
            json={
                "visitor_id": visitor_id,
                "url": f"http://localhost:3000/step-{i}",
                "event_type": "page_view",
                "timestamp": "2026-11-20T12:00:00Z",
                "metadata": {"step": i},
            },
        )
        assert track_res.status_code == 204

    # 3. Quota is now 0 remaining
    quota_res = client.get(f"/api/v1/quota-check/{visitor_id}")
    assert quota_res.json()["remaining"] == 0
    assert quota_res.json()["allowed"] is False

    # 4. Protected export endpoint blocks with 402 Payment Required
    export_res = client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id})
    assert export_res.status_code == 402
    assert export_res.json()["detail"]["error"] == "quota_exceeded"


def test_webhook_rejects_invalid_signature(client):
    """Verify forged or tampered webhook payloads are rejected with 400 Bad Request."""
    fake_event = json.dumps({"id": "evt_forged_999", "type": "checkout.session.completed"}).encode("utf-8")
    res = client.post(
        "/api/v1/webhook",
        content=fake_event,
        headers={"Stripe-Signature": "t=1700000000,v1=deadbeef", "Content-Type": "application/json"},
    )
    assert res.status_code == 400
    assert res.json()["detail"] == "Invalid signature"


def test_webhook_unlocks_premium_and_enforces_idempotency(client, isolated_db):
    """Verify valid webhook unlocks user, records payment once, and ignores duplicate retries."""
    visitor_id = "usr_test_vip_002"
    event_id = "evt_live_sim_777"
    session_id = "cs_test_sim_777"

    # Seed user at exhausted quota (20 events, is_premium = 0)
    with sqlite3.connect(isolated_db) as conn:
        conn.execute(
            "INSERT INTO visitor_usage (visitor_id, total_events, is_premium) VALUES (?, 20, 0)",
            (visitor_id,),
        )
        conn.commit()

    # Confirm user is blocked before payment
    blocked_res = client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id})
    assert blocked_res.status_code == 402

    # Construct and sign a real checkout.session.completed event
    event_payload = {
        "id": event_id,
        "object": "event",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session_id,
                "object": "checkout.session",
                "client_reference_id": visitor_id,
                "amount_total": 999,
                "currency": "usd",
            }
        },
    }
    raw_body, sig_header = sign_stripe_payload(event_payload)

    # 1. First webhook delivery -> unlocks user and records payment
    first_res = client.post(
        "/api/v1/webhook",
        content=raw_body,
        headers={"Stripe-Signature": sig_header, "Content-Type": "application/json"},
    )
    assert first_res.status_code == 200
    assert first_res.json() == {"status": "success"}

    # Rotate/retrieve raw API key for authenticated Pro request
    key_res = client.post("/api/v1/rotate-key", json={"visitor_id": visitor_id})
    assert key_res.status_code == 200
    api_key = key_res.json()["api_key"]

    # Confirm protected endpoint now returns 200 OK with X-API-Key
    unlocked_res = client.get(
        "/api/v1/export-data",
        headers={"X-Visitor-ID": visitor_id, "X-API-Key": api_key},
    )
    assert unlocked_res.status_code == 200
    assert unlocked_res.json()["tier"] == "premium"

    # 2. Duplicate webhook retry -> returns already_processed without duplicating payment row
    retry_res = client.post(
        "/api/v1/webhook",
        content=raw_body,
        headers={"Stripe-Signature": sig_header, "Content-Type": "application/json"},
    )
    assert retry_res.status_code == 200
    assert retry_res.json() == {"status": "already_processed"}

    with sqlite3.connect(isolated_db) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM payments WHERE stripe_event_id = ?",
            (event_id,),
        ).fetchone()[0]
        assert count == 1


def test_subscription_activation_and_cancellation_revokes_access(client, isolated_db):
    """Verify subscription checkout unlocks access and customer.subscription.deleted revokes it."""
    visitor_id = "usr_sub_lifecycle_003"
    sub_id = "sub_test_monthly_999"
    cust_id = "cus_test_monthly_999"

    # Seed user at exhausted free quota
    with sqlite3.connect(isolated_db) as conn:
        conn.execute(
            "INSERT INTO visitor_usage (visitor_id, total_events, is_premium) VALUES (?, 20, 0)",
            (visitor_id,),
        )
        conn.commit()

    # 1. Simulate checkout.session.completed in subscription mode
    checkout_event = {
        "id": "evt_sub_start_001",
        "object": "event",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_sub_001",
                "object": "checkout.session",
                "mode": "subscription",
                "client_reference_id": visitor_id,
                "customer": cust_id,
                "subscription": sub_id,
                "amount_total": 999,
                "currency": "usd",
            }
        },
    }
    raw_start, sig_start = sign_stripe_payload(checkout_event)
    res_start = client.post(
        "/api/v1/webhook",
        content=raw_start,
        headers={"Stripe-Signature": sig_start, "Content-Type": "application/json"},
    )
    assert res_start.status_code == 200

    # Obtain Pro API key and verify protected endpoint is unlocked (200 OK)
    key_res = client.post("/api/v1/rotate-key", json={"visitor_id": visitor_id})
    api_key = key_res.json()["api_key"]
    assert client.get(
        "/api/v1/export-data",
        headers={"X-Visitor-ID": visitor_id, "X-API-Key": api_key},
    ).status_code == 200

    # 2. Simulate customer.subscription.deleted when user cancels subscription
    cancel_event = {
        "id": "evt_sub_cancel_001",
        "object": "event",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": sub_id,
                "object": "subscription",
                "customer": cust_id,
                "metadata": {"visitor_id": visitor_id},
            }
        },
    }
    raw_cancel, sig_cancel = sign_stripe_payload(cancel_event)
    res_cancel = client.post(
        "/api/v1/webhook",
        content=raw_cancel,
        headers={"Stripe-Signature": sig_cancel, "Content-Type": "application/json"},
    )
    assert res_cancel.status_code == 200

    # Protected endpoint is now blocked again (402 Payment Required) and API key is wiped
    blocked_again = client.get(
        "/api/v1/export-data",
        headers={"X-Visitor-ID": visitor_id, "X-API-Key": api_key},
    )
    assert blocked_again.status_code == 402


def test_portal_session_requires_existing_stripe_customer(client, isolated_db):
    """Verify /api/v1/create-portal-session rejects visitors without a stripe_customer_id."""
    res = client.post("/api/v1/create-portal-session", json={"visitor_id": "usr_no_customer_004"})
    assert res.status_code == 400
    assert "No active Stripe customer" in res.json()["detail"]


def test_billing_history_returns_recorded_events(client, isolated_db):
    """Verify /api/v1/billing-history returns a visitor's payment and cancellation events newest-first."""
    visitor_id = "usr_history_005"

    empty_res = client.get("/api/v1/billing-history", headers={"X-Visitor-ID": visitor_id})
    assert empty_res.status_code == 200
    assert empty_res.json()["total_records"] == 0

    with sqlite3.connect(isolated_db) as conn:
        conn.execute(
            """INSERT INTO payments (stripe_event_id, checkout_session_id, visitor_id, amount_total, currency, event_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("evt_hist_1", "cs_hist_1", visitor_id, 999, "usd", "checkout.session.completed"),
        )
        conn.execute(
            """INSERT INTO payments (stripe_event_id, checkout_session_id, visitor_id, amount_total, currency, event_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("evt_hist_2", "sub_hist_1", visitor_id, 0, "usd", "customer.subscription.deleted"),
        )
        conn.commit()

    res = client.get("/api/v1/billing-history", headers={"X-Visitor-ID": visitor_id})
    assert res.status_code == 200
    body = res.json()
    assert body["total_records"] == 2
    assert body["history"][0]["event_type"] == "customer.subscription.deleted"
    assert body["history"][1]["amount_cents"] == 999


def test_pro_api_key_authentication_and_rotation(client, isolated_db):
    """Verify Pro users must send a valid X-API-Key, raw keys are never stored in SQLite, and rotation works."""
    visitor_id = "usr_apikey_006"

    # 1. Free users cannot generate an API key
    forbidden_res = client.post("/api/v1/rotate-key", json={"visitor_id": visitor_id})
    assert forbidden_res.status_code == 403

    # 2. Simulate subscription activation via webhook
    checkout_event = {
        "id": "evt_apikey_sub_001",
        "object": "event",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_apikey_001",
                "object": "checkout.session",
                "mode": "subscription",
                "client_reference_id": visitor_id,
                "customer": "cus_apikey_001",
                "subscription": "sub_apikey_001",
                "amount_total": 999,
                "currency": "usd",
            }
        },
    }
    raw_payload, sig = sign_stripe_payload(checkout_event)
    assert client.post(
        "/api/v1/webhook",
        content=raw_payload,
        headers={"Stripe-Signature": sig, "Content-Type": "application/json"},
    ).status_code == 200

    # 3. Attempting to export with only X-Visitor-ID (no X-API-Key) returns 401 Unauthorized
    no_key_res = client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id})
    assert no_key_res.status_code == 401

    # 4. Rotate API key and verify raw key is NOT stored in SQLite
    rotate_res = client.post("/api/v1/rotate-key", json={"visitor_id": visitor_id})
    assert rotate_res.status_code == 200
    new_raw_key = rotate_res.json()["api_key"]
    assert new_raw_key.startswith("ak_live_")

    with sqlite3.connect(isolated_db) as conn:
        stored_hash, stored_prefix = conn.execute(
            "SELECT api_key_hash, api_key_prefix FROM visitor_usage WHERE visitor_id = ?",
            (visitor_id,),
        ).fetchone()
        assert stored_hash != new_raw_key
        assert len(stored_hash) == 64

    # 5. Wrong API key returns 401; valid API key returns 200
    bad_key_res = client.get(
        "/api/v1/export-data",
        headers={"X-Visitor-ID": visitor_id, "X-API-Key": "ak_live_wrong_key"},
    )
    assert bad_key_res.status_code == 401

    ok_res = client.get(
        "/api/v1/export-data",
        headers={"X-Visitor-ID": visitor_id, "X-API-Key": new_raw_key},
    )
    assert ok_res.status_code == 200
    assert ok_res.json()["tier"] == "premium"
