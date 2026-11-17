# Activity Monetization & Subscription Engine

A full-stack usage-based monetization architecture built with **FastAPI**, **SQLite**, **vanilla JavaScript**, and **Stripe Billing**. It tracks user activity in real time, enforces free-tier usage quotas (`HTTP 402 Payment Required`), handles recurring monthly subscriptions via Stripe Checkout and Customer Portal, and processes cryptographically verified webhooks with database-level idempotency.

## Architecture Overview
