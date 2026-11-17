import json
import time
import sqlite3
import pytest
from fastapi.testclient import TestClient
import stripe

import main

TEST_WEBHOOK_SECRET = "whsec_test_secret_1234567890"


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect main.py to a fresh temporary SQLite database for every test."""
    test_db_path = str(tmp_path / "test_analytics.db")
    monkeypatch.setattr(main, "DB_NAME", test_db_path)
    monkeypatch.setattr(main, "WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
    main.init_db()
    yield test_db_path


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c


def sign_stripe_payload(payload_dict: dict, secret: str = TEST_WEBHOOK_SECRET) -> tuple[str, str]:
    """Generate a valid Stripe-Signature header matching Stripe's HMAC-SHA256 spec."""
    payload_str = json.dumps(payload_dict)
    timestamp = int(time.time())
    signed_payload = f"{timestamp}.{payload_str}"
    signature = stripe.WebhookSignature._compute_signature(signed_payload, secret)
    header = f"t={timestamp},v1={signature}"
    return payload_str, header


def test_quota_tracking_and_402_blocking(client):
    """Verify free users can log up to FREE_LIMIT events, then get blocked with 402."""
    visitor_id = "usr_test_quota_001"

    # 1. Fresh user starts with full quota allowed
    res = client.get(f"/api/v1/quota-check/{visitor_id}")
    assert res.status_code == 200
    assert res.json()["allowed"] is True
    assert res.json()["remaining"] == main.FREE_LIMIT

    # 2. Log FREE_LIMIT events
    for i in range(main.FREE_LIMIT):
        track_res = client.post(
            "/api/v1/track",
            json={
                "visitor_id": visitor_id,
                "url": "http://localhost:3000/",
                "event_type": "click",
                "timestamp": "2026-11-13T12:00:00Z",
                "metadata": {"step": i},
            },
        )
        assert track_res.status_code == 204

    # 3. Quota check now reports exhausted
    quota_res = client.get(f"/api/v1/quota-check/{visitor_id}")
    assert quota_res.json()["allowed"] is False
    assert quota_res.json()["remaining"] == 0
    assert quota_res.json()["total_events"] == main.FREE_LIMIT

    # 4. Protected endpoint rejects the user with 402 Payment Required
    export_res = client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id})
    assert export_res.status_code == 402
    assert export_res.json()["detail"]["error"] == "quota_exceeded"


def test_webhook_rejects_invalid_signature(client):
    """Verify forged or tampered webhook payloads are rejected with 400 Bad Request."""
    event_payload = {
        "id": "evt_forged_999",
        "object": "event",
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_test_123", "client_reference_id": "usr_hacker"}},
    }

    res = client.post(
        "/api/v1/webhook",
        data=json.dumps(event_payload),
        headers={"Stripe-Signature": "t=123456,v1=invalid_hmac_signature"},
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

    # Confirm protected endpoint now returns 200 OK
    unlocked_res = client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id})
    assert unlocked_res.status_code == 200
    assert unlocked_res.json()["tier"] == "premium"

    # 2. Second webhook delivery (Stripe retry) -> safely ignored
    second_res = client.post(
        "/api/v1/webhook",
        content=raw_body,
        headers={"Stripe-Signature": sig_header, "Content-Type": "application/json"},
    )
    assert second_res.status_code == 200
    assert second_res.json() == {"status": "already_processed"}

    # 3. Verify payments audit ledger has exactly 1 row (no duplicates)
    with sqlite3.connect(isolated_db) as conn:
        rows = conn.execute("SELECT stripe_event_id, visitor_id, amount_total FROM payments").fetchall()
    assert len(rows) == 1
    assert rows[0] == (event_id, visitor_id, 999)
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

    # Protected endpoint is now unlocked (200 OK)
    assert client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id}).status_code == 200

    # 2. Simulate customer.subscription.deleted (cancellation)
    cancel_event = {
        "id": "evt_sub_cancel_002",
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

    # Protected endpoint is now locked again (402 Payment Required)
    revoked_res = client.get("/api/v1/export-data", headers={"X-Visitor-ID": visitor_id})
    assert revoked_res.status_code == 402
def test_portal_session_requires_existing_stripe_customer(client):
    """Verify visitors without a stripe_customer_id cannot open a billing portal."""
    res = client.post("/api/v1/create-portal-session", json={"visitor_id": "usr_no_customer"})
    assert res.status_code == 400
    assert "No active Stripe customer" in res.json()["detail"]


def test_billing_history_returns_recorded_events(client, isolated_db):
    """Verify /api/v1/billing-history returns a visitor's payment and cancellation events newest-first."""
    visitor_id = "usr_history_005"

    # 1. Visitor with no payments gets an empty list
    empty_res = client.get("/api/v1/billing-history", headers={"X-Visitor-ID": visitor_id})
    assert empty_res.status_code == 200
    assert empty_res.json()["total_records"] == 0

    # 2. Seed a subscription activation and a cancellation event
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
