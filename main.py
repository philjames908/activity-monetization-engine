import os
import hmac
import hashlib
import secrets
import sqlite3
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import stripe

load_dotenv()

app = FastAPI(title="Activity Monetization Engine", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

stripe.api_key = os.getenv("STRIPE_API_KEY", "")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DB_NAME = "analytics.db"
FREE_LIMIT = 20


def generate_api_key() -> tuple[str, str, str]:
    """Generate a raw API key, its SHA-256 hex digest, and a display prefix."""
    raw_key = f"ak_live_{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    key_prefix = f"{raw_key[:12]}..."
    return raw_key, key_hash, key_prefix


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_id TEXT NOT NULL,
                url TEXT NOT NULL,
                referrer TEXT,
                event_type TEXT NOT NULL,
                metadata TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS visitor_usage (
                visitor_id TEXT PRIMARY KEY,
                total_events INTEGER DEFAULT 0,
                is_premium INTEGER DEFAULT 0,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                api_key_hash TEXT,
                api_key_prefix TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stripe_event_id TEXT UNIQUE NOT NULL,
                checkout_session_id TEXT NOT NULL,
                visitor_id TEXT NOT NULL,
                amount_total INTEGER,
                currency TEXT,
                event_type TEXT DEFAULT 'checkout.session.completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Non-destructive schema migration for existing local databases
        usage_cols = [r[1] for r in cursor.execute("PRAGMA table_info(visitor_usage)").fetchall()]
        if "stripe_customer_id" not in usage_cols:
            cursor.execute("ALTER TABLE visitor_usage ADD COLUMN stripe_customer_id TEXT")
        if "stripe_subscription_id" not in usage_cols:
            cursor.execute("ALTER TABLE visitor_usage ADD COLUMN stripe_subscription_id TEXT")
        if "api_key_hash" not in usage_cols:
            cursor.execute("ALTER TABLE visitor_usage ADD COLUMN api_key_hash TEXT")
        if "api_key_prefix" not in usage_cols:
            cursor.execute("ALTER TABLE visitor_usage ADD COLUMN api_key_prefix TEXT")

        pay_cols = [r[1] for r in cursor.execute("PRAGMA table_info(payments)").fetchall()]
        if "event_type" not in pay_cols:
            cursor.execute("ALTER TABLE payments ADD COLUMN event_type TEXT DEFAULT 'checkout.session.completed'")

        conn.commit()


init_db()


class TrackEvent(BaseModel):
    visitor_id: str
    url: str
    referrer: Optional[str] = None
    event_type: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CheckoutRequest(BaseModel):
    visitor_id: str
    price_id: Optional[str] = None


def log_event_worker(event: TrackEvent, client_ip: str):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO activity_logs (visitor_id, url, referrer, event_type, metadata, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event.visitor_id,
            event.url,
            event.referrer,
            event.event_type,
            str(event.metadata),
            client_ip
        ))
        cursor.execute("""
            INSERT INTO visitor_usage (visitor_id, total_events, is_premium)
            VALUES (?, 1, 0)
            ON CONFLICT(visitor_id) DO UPDATE SET total_events = total_events + 1
        """, (event.visitor_id,))
        conn.commit()


async def verify_access(
    x_visitor_id: str = Header(..., description="Visitor ID header"),
    x_api_key: Optional[str] = Header(None, description="Pro Subscriber API Key"),
):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT total_events, is_premium, api_key_hash FROM visitor_usage WHERE visitor_id = ?",
            (x_visitor_id,)
        )
        row = cursor.fetchone()

    if not row:
        return {"visitor_id": x_visitor_id, "tier": "free"}

    total_events, is_premium, stored_hash = row

    if is_premium:
        if stored_hash:
            if not x_api_key:
                raise HTTPException(
                    status_code=401,
                    detail={"error": "missing_api_key", "message": "Pro tier requires an X-API-Key header."}
                )
            provided_hash = hash_api_key(x_api_key)
            if not hmac.compare_digest(provided_hash, stored_hash):
                raise HTTPException(
                    status_code=401,
                    detail={"error": "invalid_api_key", "message": "Provided X-API-Key is invalid or revoked."}
                )
        return {"visitor_id": x_visitor_id, "tier": "premium"}

    if total_events >= FREE_LIMIT:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "quota_exceeded",
                "message": "Free quota exhausted. Subscribe to Pro to continue.",
                "total_events": total_events
            }
        )

    return {"visitor_id": x_visitor_id, "tier": "free"}


@app.post("/api/v1/track", status_code=204)
async def track_activity(event: TrackEvent, request: Request, background_tasks: BackgroundTasks):
    client_ip = request.client.host if request.client else "unknown"
    background_tasks.add_task(log_event_worker, event, client_ip)
    return None


@app.get("/api/v1/quota-check/{visitor_id}")
async def check_quota(visitor_id: str):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT total_events, is_premium, stripe_subscription_id, api_key_prefix FROM visitor_usage WHERE visitor_id = ?",
            (visitor_id,)
        )
        row = cursor.fetchone()

    if not row:
        return {
            "allowed": True,
            "remaining": FREE_LIMIT,
            "is_premium": False,
            "subscription_id": None,
            "api_key_prefix": None,
        }

    total_events, is_premium, sub_id, key_prefix = row
    if is_premium:
        return {
            "allowed": True,
            "total_events": total_events,
            "remaining": -1,
            "is_premium": True,
            "subscription_id": sub_id,
            "api_key_prefix": key_prefix,
        }

    remaining = max(0, FREE_LIMIT - total_events)
    return {
        "allowed": total_events < FREE_LIMIT,
        "total_events": total_events,
        "remaining": remaining,
        "is_premium": False,
        "subscription_id": sub_id,
        "api_key_prefix": None,
    }


@app.post("/api/v1/rotate-key")
async def rotate_api_key(payload: CheckoutRequest):
    """Issue or rotate a Pro subscriber's API key, storing only its SHA-256 digest."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT is_premium FROM visitor_usage WHERE visitor_id = ?",
            (payload.visitor_id,)
        )
        row = cursor.fetchone()

        if not row or not row[0]:
            raise HTTPException(
                status_code=403,
                detail="Active Pro subscription required to generate or rotate an API key."
            )

        raw_key, key_hash, key_prefix = generate_api_key()
        cursor.execute(
            "UPDATE visitor_usage SET api_key_hash = ?, api_key_prefix = ? WHERE visitor_id = ?",
            (key_hash, key_prefix, payload.visitor_id)
        )
        conn.commit()

    return {
        "visitor_id": payload.visitor_id,
        "api_key": raw_key,
        "api_key_prefix": key_prefix,
        "warning": "Store this key securely now; it will not be shown again."
    }


@app.get("/api/v1/export-data")
async def export_user_data(user: dict = Depends(verify_access)):
    visitor_id = user["visitor_id"]
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, url, event_type, created_at FROM activity_logs WHERE visitor_id = ? ORDER BY id DESC LIMIT 10",
            (visitor_id,)
        )
        logs = [
            {"id": r0, "url": r1, "event_type": r2, "timestamp": r3}
            for r0, r1, r2, r3 in cursor.fetchall()
        ]
    return {
        "status": "authorized",
        "tier": user["tier"],
        "records_exported": len(logs),
        "data": logs
    }


@app.post("/api/v1/create-checkout-session")
async def create_checkout(payload: CheckoutRequest):
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": "Pro Activity Pass (Monthly)"},
                    "unit_amount": 999,
                    "recurring": {"interval": "month"},
                },
                "quantity": 1,
            }],
            mode="subscription",
            client_reference_id=payload.visitor_id,
            subscription_data={
                "metadata": {"visitor_id": payload.visitor_id}
            },
            success_url="http://localhost:3000/?upgraded=true",
            cancel_url="http://localhost:3000/?canceled=true",
        )
        return {"checkout_url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/create-portal-session")
async def create_portal_session(payload: CheckoutRequest):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT stripe_customer_id FROM visitor_usage WHERE visitor_id = ?",
            (payload.visitor_id,)
        )
        row = cursor.fetchone()

    if not row or not row[0]:
        raise HTTPException(
            status_code=400,
            detail="No active Stripe customer record found for this visitor."
        )

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=row[0],
            return_url="http://localhost:3000/",
        )
        return {"portal_url": portal_session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/billing-history")
async def get_billing_history(x_visitor_id: str = Header(..., description="Visitor ID header")):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT stripe_event_id, checkout_session_id, amount_total, currency, event_type, created_at
            FROM payments
            WHERE visitor_id = ?
            ORDER BY id DESC
        """, (x_visitor_id,))
        rows = cursor.fetchall()

    records = [
        {
            "event_id": r[0],
            "reference_id": r[1],
            "amount_cents": r[2] or 0,
            "currency": (r[3] or "usd").upper(),
            "event_type": r[4],
            "timestamp": r[5],
        }
        for r in rows
    ]

    return {
        "visitor_id": x_visitor_id,
        "total_records": len(records),
        "history": records,
    }


@app.post("/api/v1/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=stripe_signature,
            secret=WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_id = event["id"]
    event_type = event["type"]
    data_obj = event["data"]["object"]

    if event_type == "checkout.session.completed":
        session_id = getattr(data_obj, "id", "unknown")
        visitor_id = getattr(data_obj, "client_reference_id", None)
        customer_id = getattr(data_obj, "customer", None)
        subscription_id = getattr(data_obj, "subscription", None)
        amount_total = getattr(data_obj, "amount_total", 0)
        currency = getattr(data_obj, "currency", "usd")

        if visitor_id:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        INSERT INTO payments (stripe_event_id, checkout_session_id, visitor_id, amount_total, currency, event_type)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (event_id, session_id, visitor_id, amount_total, currency, event_type))
                except sqlite3.IntegrityError:
                    print(f"[WEBHOOK] Duplicate event ignored: {event_id}")
                    return {"status": "already_processed"}

                _, key_hash, key_prefix = generate_api_key()
                cursor.execute("""
                    INSERT INTO visitor_usage (
                        visitor_id, total_events, is_premium, stripe_customer_id,
                        stripe_subscription_id, api_key_hash, api_key_prefix
                    )
                    VALUES (?, 0, 1, ?, ?, ?, ?)
                    ON CONFLICT(visitor_id) DO UPDATE SET
                        is_premium = 1,
                        stripe_customer_id = excluded.stripe_customer_id,
                        stripe_subscription_id = excluded.stripe_subscription_id,
                        api_key_hash = COALESCE(visitor_usage.api_key_hash, excluded.api_key_hash),
                        api_key_prefix = COALESCE(visitor_usage.api_key_prefix, excluded.api_key_prefix)
                """, (visitor_id, customer_id, subscription_id, key_hash, key_prefix))
                conn.commit()
            print(f"[WEBHOOK] Activated subscription ({subscription_id}) & provisioned API key for: {visitor_id}")

    elif event_type == "customer.subscription.deleted":
        subscription_id = getattr(data_obj, "id", None)
        metadata = getattr(data_obj, "metadata", None)
        visitor_id = getattr(metadata, "visitor_id", None) if metadata else None

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            if not visitor_id and subscription_id:
                cursor.execute(
                    "SELECT visitor_id FROM visitor_usage WHERE stripe_subscription_id = ?",
                    (subscription_id,)
                )
                row = cursor.fetchone()
                if row:
                    visitor_id = row[0]

            if visitor_id:
                try:
                    cursor.execute("""
                        INSERT INTO payments (stripe_event_id, checkout_session_id, visitor_id, amount_total, currency, event_type)
                        VALUES (?, ?, ?, 0, 'usd', ?)
                    """, (event_id, subscription_id or "sub_deleted", visitor_id, event_type))
                except sqlite3.IntegrityError:
                    print(f"[WEBHOOK] Duplicate cancellation ignored: {event_id}")
                    return {"status": "already_processed"}

                cursor.execute("""
                    UPDATE visitor_usage
                    SET is_premium = 0, api_key_hash = NULL, api_key_prefix = NULL
                    WHERE visitor_id = ?
                """, (visitor_id,))
                conn.commit()
                print(f"[WEBHOOK] Subscription canceled ({subscription_id}) -> Revoked access & API key for: {visitor_id}")

    return {"status": "success"}
