import os
import sqlite3
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import stripe

load_dotenv()

app = FastAPI(title="Activity Monetization Engine", version="2.0.0")

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
                stripe_subscription_id TEXT
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

        # Migrate existing local tables cleanly if columns are missing
        usage_cols = [r[1] for r in cursor.execute("PRAGMA table_info(visitor_usage)").fetchall()]
        if "stripe_customer_id" not in usage_cols:
            cursor.execute("ALTER TABLE visitor_usage ADD COLUMN stripe_customer_id TEXT")
        if "stripe_subscription_id" not in usage_cols:
            cursor.execute("ALTER TABLE visitor_usage ADD COLUMN stripe_subscription_id TEXT")

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


async def verify_access(x_visitor_id: str = Header(..., description="Visitor ID header")):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT total_events, is_premium FROM visitor_usage WHERE visitor_id = ?", (x_visitor_id,))
        row = cursor.fetchone()

    if not row:
        return {"visitor_id": x_visitor_id, "tier": "free"}

    total_events, is_premium = row
    if is_premium:
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
            "SELECT total_events, is_premium, stripe_subscription_id FROM visitor_usage WHERE visitor_id = ?",
            (visitor_id,)
        )
        row = cursor.fetchone()

    if not row:
        return {"allowed": True, "remaining": FREE_LIMIT, "is_premium": False, "subscription_id": None}

    total_events, is_premium, sub_id = row
    if is_premium:
        return {
            "allowed": True,
            "total_events": total_events,
            "remaining": -1,
            "is_premium": True,
            "subscription_id": sub_id
        }

    remaining = max(0, FREE_LIMIT - total_events)
    return {
        "allowed": total_events < FREE_LIMIT,
        "total_events": total_events,
        "remaining": remaining,
        "is_premium": False,
        "subscription_id": sub_id
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

    # 1. Subscription started via Checkout
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

                cursor.execute("""
                    INSERT INTO visitor_usage (visitor_id, total_events, is_premium, stripe_customer_id, stripe_subscription_id)
                    VALUES (?, 0, 1, ?, ?)
                    ON CONFLICT(visitor_id) DO UPDATE SET
                        is_premium = 1,
                        stripe_customer_id = excluded.stripe_customer_id,
                        stripe_subscription_id = excluded.stripe_subscription_id
                """, (visitor_id, customer_id, subscription_id))
                conn.commit()
            print(f"[WEBHOOK] Activated subscription ({subscription_id}) for visitor: {visitor_id}")

    # 2. Subscription canceled or expired -> Revoke Premium access
    elif event_type == "customer.subscription.deleted":
        subscription_id = getattr(data_obj, "id", None)
        customer_id = getattr(data_obj, "customer", None)
        metadata = getattr(data_obj, "metadata", None)
        visitor_id = getattr(metadata, "visitor_id", None) if metadata else None

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            # Fallback lookup by stripe_subscription_id if metadata wasn't attached
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
                    SET is_premium = 0
                    WHERE visitor_id = ?
                """, (visitor_id,))
                conn.commit()
                print(f"[WEBHOOK] Subscription canceled ({subscription_id}) -> Revoked access for: {visitor_id}")

    return {"status": "success"}


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

    customer_id = row[0]

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=customer_id,
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
