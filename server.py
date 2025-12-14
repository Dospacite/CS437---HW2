
import os
import time
import base64
import re
import json
import ipaddress
from uuid import uuid4
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from fastapi import FastAPI, Request, Response
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import httpx
import aiosqlite
import uvicorn

# Database and log paths
DATABASE_PATH = "data/tracking.db"
LOG_FILE = "logs/tracking.log"

# 1x1 Transparent GIF (base64 decoded) - used for tracking pixel
TRANSPARENT_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)

# Known bot/scanner User-Agent patterns
# These are commonly used by email security gateways and link scanners
BOT_UA_PATTERNS = [
    r"GoogleImageProxy",           # Gmail's image proxy
    r"Microsoft Defender",         # Microsoft Defender SmartScreen
    r"SmartScreen",                # Microsoft SmartScreen
    r"Cisco IronPort",             # Cisco email security
    r"Barracuda",                  # Barracuda email security
    r"Proofpoint",                 # Proofpoint URL Defense
    r"URL Defense",                # Proofpoint URL Defense
    r"Symantec",                   # Symantec email security
    r"McAfee",                     # McAfee email security
    r"Mimecast",                   # Mimecast email security
    r"FireEye",                    # FireEye email security
    r"Trend Micro",                # Trend Micro email security
    r"Sophos",                     # Sophos email security
    r"FortiGuard",                 # Fortinet email security
    r"Websense",                   # Websense/Forcepoint
    r"MessageLabs",                # Symantec MessageLabs
    r"bot",                        # Generic bot indicator
    r"crawler",                    # Web crawler
    r"spider",                     # Web spider
    r"headless",                   # Headless browser
    r"PhantomJS",                  # PhantomJS headless browser
    r"Selenium",                   # Selenium automation
    r"python-requests",            # Python requests library
    r"curl",                       # curl command-line tool
    r"wget",                       # wget command-line tool
    r"libwww",                     # Perl LWP library
    r"Java/",                      # Java HTTP client
]

# Compile patterns for efficient matching
BOT_UA_REGEX = re.compile("|".join(BOT_UA_PATTERNS), re.IGNORECASE)

# Normal browser User-Agent patterns (indicators of real humans)
BROWSER_UA_PATTERNS = [
    r"Chrome/\d+",                 # Google Chrome
    r"Firefox/\d+",                # Mozilla Firefox
    r"Safari/\d+",                 # Apple Safari
    r"Edg/\d+",                    # Microsoft Edge (Chromium)
    r"Edge/\d+",                   # Microsoft Edge (Legacy)
    r"MSIE \d+",                   # Internet Explorer
    r"Trident/\d+",                # IE Trident engine
    r"Opera/\d+",                  # Opera browser
    r"OPR/\d+",                    # Opera (Chromium)
]

BROWSER_UA_REGEX = re.compile("|".join(BROWSER_UA_PATTERNS), re.IGNORECASE)

# Load datacenter CIDR ranges from file
DATACENTERS_FILE = "datacenters.txt"

def load_datacenter_networks():
    networks = []
    try:
        with open(DATACENTERS_FILE, "r") as f:
            for line in f:
                cidr = line.strip()
                if cidr:
                    try:
                        networks.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass  # Skip invalid CIDRs
    except FileNotFoundError:
        print(f"[WARNING] {DATACENTERS_FILE} not found, datacenter IP detection disabled")
    return networks

DATACENTER_NETWORKS = load_datacenter_networks()

# IP lookup cache to avoid repeated API calls
IP_CACHE: Dict[str, str] = {}

app = FastAPI(
    title="Phishing Email Tracking System",
    description="Bot vs Human detection for email tracking - CS437/SEC537 Part 3",
    version="1.0.0"
)

templates = Jinja2Templates(directory="templates")

async def init_database():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS tracking_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                user_agent TEXT,
                request_method TEXT,
                verdict TEXT,
                reason TEXT,
                extra_data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Index for fast lookups by tracking_id
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_tracking_id
            ON tracking_events(tracking_id)
        """)

        # Index for timestamp-based queries (rapid access detection)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON tracking_events(timestamp)
        """)

        await db.commit()


async def log_event(
    tracking_id: str,
    event_type: str,
    ip: str,
    user_agent: str,
    method: str,
    verdict: str,
    reason: str,
    extra_data: dict = None
):
    timestamp = datetime.now().isoformat()

    # Console output with clear formatting for easy monitoring
    print(f"\n{'='*70}")
    print(f"[{timestamp}] TRACKING EVENT")
    print(f"{'='*70}")
    print(f"  Tracking ID   : {tracking_id}")
    print(f"  Event Type    : {event_type}")
    print(f"  Source IP     : {ip}")
    print(f"  User-Agent    : {user_agent[:80]}{'...' if len(user_agent) > 80 else ''}")
    print(f"  Method        : {method}")
    print(f"  >>> VERDICT   : [{verdict}]")
    print(f"  >>> Reason    : {reason}")
    print(f"{'='*70}\n")

    # Database storage for persistence and querying
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO tracking_events
            (tracking_id, event_type, source_ip, user_agent,
             request_method, verdict, reason, extra_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tracking_id, event_type, ip, user_agent,
            method, verdict, reason,
            json.dumps(extra_data) if extra_data else None
        ))
        await db.commit()

    # Also write to log file
    with open(LOG_FILE, "a") as f:
        log_entry = {
            "timestamp": timestamp,
            "tracking_id": tracking_id,
            "event_type": event_type,
            "source_ip": ip,
            "user_agent": user_agent,
            "method": method,
            "verdict": verdict,
            "reason": reason
        }
        f.write(json.dumps(log_entry) + "\n")


async def get_recent_access_count(tracking_id: str, window_seconds: int = 10) -> int:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute("""
            SELECT COUNT(*) FROM tracking_events
            WHERE tracking_id = ?
            AND datetime(timestamp) > datetime('now', ?)
        """, (tracking_id, f'-{window_seconds} seconds'))

        row = await cursor.fetchone()
        return row[0] if row else 0

# ============================================================================
# IP REPUTATION FUNCTIONS
# ============================================================================

def is_datacenter_ip_local(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in DATACENTER_NETWORKS:
            if ip_obj in network:
                return True
    except ValueError:
        pass  # Invalid IP format
    return False


async def check_ip_type(ip: str) -> str:
    # Check cache first
    if ip in IP_CACHE:
        return IP_CACHE[ip]

    # Check local datacenter CIDR ranges first (fast path)
    if is_datacenter_ip_local(ip):
        IP_CACHE[ip] = "datacenter"
        return "datacenter"

    # Fallback: Query ipinfo.io API for additional checks
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # ipinfo.io free tier (no token needed for basic info)
            response = await client.get(f"https://ipinfo.io/{ip}/json")

            if response.status_code == 200:
                data = response.json()

                org = data.get("org", "").lower()
                hostname = data.get("hostname", "").lower()

                # Check for datacenter indicators in org/hostname
                datacenter_keywords = [
                    "amazon", "aws", "microsoft", "azure", "google", "cloud",
                    "digitalocean", "linode", "vultr", "ovh", "hetzner",
                    "cloudflare", "akamai", "fastly", "hosting", "server",
                    "datacenter", "data center", "colo", "vps", "dedicated"
                ]

                for keyword in datacenter_keywords:
                    if keyword in org or keyword in hostname:
                        IP_CACHE[ip] = "datacenter"
                        return "datacenter"

                # Default to residential if no datacenter indicators found
                IP_CACHE[ip] = "residential"
                return "residential"

    except Exception as e:
        print(f"[WARNING] IP lookup failed for {ip}: {e}")

    # If API fails, mark as unknown
    IP_CACHE[ip] = "unknown"
    return "unknown"

# ============================================================================
# DETECTION ENGINE
# ============================================================================

async def analyze_request(
    ip: str,
    user_agent: str,
    method: str,
    sent_timestamp: int,
    current_timestamp: int,
    tracking_id: str,
    has_js_verification: bool,
    mouse_movements: List[Dict] = None,
    fingerprint: Dict = None,
    js_executed: bool = False
) -> Tuple[str, str]:
    reasons_bot = []
    reasons_human = []

    # User agent detection only for verification link, not for pixel tracking
    if has_js_verification:
        if BOT_UA_REGEX.search(user_agent):
            reasons_bot.append(f"Bot UA pattern detected")
        elif BROWSER_UA_REGEX.search(user_agent):
            reasons_human.append("Standard browser User-Agent")
        elif not user_agent or user_agent.strip() == "":
            reasons_bot.append("Empty User-Agent")
        else:
            reasons_bot.append(f"Unusual User-Agent")

    if method == "HEAD":
        reasons_bot.append("HEAD request (typical of link scanners)")

    time_delta = current_timestamp - sent_timestamp

    if time_delta < 0:
        # Timestamp is in the future - manipulation or clock skew
        reasons_bot.append("Timestamp manipulation detected")
    elif time_delta <= 2:
        # Immediate access - very likely automated scanner
        reasons_bot.append(f"Immediate access ({time_delta}s after delivery)")
    elif time_delta > 5:
        # Natural delay - more likely human
        reasons_human.append(f"Natural delay ({time_delta}s after delivery)")
    # 2-5 seconds is ambiguous, don't add to either list

    ip_type = await check_ip_type(ip)

    if ip_type == "datacenter":
        reasons_bot.append(f"Data center IP detected")
    elif ip_type == "residential":
        reasons_human.append("Residential IP address")

    access_count = await get_recent_access_count(tracking_id, window_seconds=10)

    if access_count > 3:
        reasons_bot.append(f"Rapid repeated access ({access_count} times in 10s)")


    if has_js_verification:
        if not js_executed:
            reasons_bot.append("No JavaScript execution")
        else:
            reasons_human.append("JavaScript executed successfully")

            if mouse_movements and len(mouse_movements) >= 2:
                # Verify movements are realistic (not all same position)
                unique_positions = set((m.get('x', 0), m.get('y', 0)) for m in mouse_movements)
                if len(unique_positions) > 1:
                    reasons_human.append(f"Mouse movement detected ({len(mouse_movements)} events)")
                else:
                    reasons_bot.append("Fake mouse movement (all same position)")
            elif mouse_movements and len(mouse_movements) == 1:
                # Only one movement event - suspicious
                pass  # Ambiguous
            # No mouse movements with JS - could be touch device, don't penalize

            if fingerprint:
                # Check for essential fingerprint properties
                has_screen = fingerprint.get('screenWidth') and fingerprint.get('screenHeight')
                has_timezone = fingerprint.get('timezone')
                has_language = fingerprint.get('language')

                if has_screen and has_timezone and has_language:
                    reasons_human.append("Valid browser fingerprint")
                elif not has_screen:
                    reasons_bot.append("Invalid screen dimensions in fingerprint")
            else:
                reasons_bot.append("No browser fingerprint received")
    else:
        # Tracking pixel - JS verification not possible
        reasons_bot.append("No JS verification possible (tracking pixel)")


    # Weight the evidence - some indicators are stronger than others
    bot_score = len(reasons_bot)
    human_score = len(reasons_human)

    # Strong bot indicators get extra weight
    strong_bot_indicators = [
        "Bot UA pattern",
        "HEAD request",
        "Immediate access",
        "Data center IP",
        "Rapid repeated access",
        "No JavaScript execution",
        "Empty User-Agent"
    ]

    for indicator in strong_bot_indicators:
        if any(indicator in r for r in reasons_bot):
            bot_score += 2  # Extra weight for strong indicators

    # Make final decision
    if bot_score > human_score:
        verdict = "BOT"
        reason = "; ".join(reasons_bot) if reasons_bot else "Insufficient human indicators"
    else:
        verdict = "HUMAN"
        reason = "; ".join(reasons_human) if reasons_human else "No bot indicators found"

    return verdict, reason

@app.on_event("startup")
async def startup():
    # Create required directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("templates", exist_ok=True)

    # Initialize database
    await init_database()

    print("Server started successfully!")


@app.get("/generate")
async def generate_tracking_urls(request: Request, dest: str = "https://example.com"):
    """
    Generate tracking URLs with unique ID and embedded timestamp.

    Usage: GET /generate?dest=https://target-site.com

    Returns pixel URL for email open tracking and click URL for link tracking.
    """
    tracking_id = str(uuid4())
    sent_timestamp = int(time.time())
    encoded_dest = base64.urlsafe_b64encode(dest.encode()).decode()

    # Detect base URL from request
    base_url = str(request.base_url).rstrip("/")

    return_dict = {
        "tracking_id": tracking_id,
        "sent_timestamp": sent_timestamp,
        "sent_time_human": datetime.fromtimestamp(sent_timestamp).isoformat(),
        "pixel_url": f"{base_url}/pixel/{tracking_id}?t={sent_timestamp}",
        "click_url": f"{base_url}/click/{tracking_id}?t={sent_timestamp}&dest={encoded_dest}",
        "destination": dest
    }
    return_dict["usage"] = f"<img src='{return_dict['pixel_url']}' width='1' height='1' style='display:none;' alt=''><a href='{return_dict['click_url']}'>Click here</a>"
    return return_dict


@app.get("/stats/{tracking_id}")
async def get_tracking_stats(tracking_id: str):
    """
    View all tracking events for a specific tracking ID.
    Useful for analyzing the detection results.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM tracking_events
            WHERE tracking_id = ?
            ORDER BY timestamp DESC
        """, (tracking_id,))
        rows = await cursor.fetchall()

        events = []
        for row in rows:
            event = dict(row)
            # Parse extra_data JSON if present
            if event.get('extra_data'):
                try:
                    event['extra_data'] = json.loads(event['extra_data'])
                except:
                    pass
            events.append(event)

        # Calculate summary
        bot_count = sum(1 for e in events if e.get('verdict') == 'BOT')
        human_count = sum(1 for e in events if e.get('verdict') == 'HUMAN')

        return {
            "tracking_id": tracking_id,
            "total_events": len(events),
            "summary": {
                "bot_detections": bot_count,
                "human_detections": human_count
            },
            "events": events
        }

@app.get("/pixel/{tracking_id}")
async def track_pixel(tracking_id: str, t: int, request: Request):
    # Capture request metadata
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    request_method = request.method
    current_time = int(time.time())

    # Run bot detection analysis
    verdict, reason = await analyze_request(
        ip=client_ip,
        user_agent=user_agent,
        method=request_method,
        sent_timestamp=t,
        current_timestamp=current_time,
        tracking_id=tracking_id,
        has_js_verification=False  # Pixels can't run JavaScript
    )

    # Log the tracking event
    await log_event(
        tracking_id=tracking_id,
        event_type="pixel_open",
        ip=client_ip,
        user_agent=user_agent,
        method=request_method,
        verdict=verdict,
        reason=reason
    )

    # Return transparent 1x1 GIF with cache-busting headers
    return Response(
        content=TRANSPARENT_GIF,
        media_type="image/gif",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.head("/pixel/{tracking_id}")
async def track_pixel_head(tracking_id: str, t: int, request: Request):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    await log_event(
        tracking_id=tracking_id,
        event_type="pixel_head",
        ip=client_ip,
        user_agent=user_agent,
        method="HEAD",
        verdict="BOT",
        reason="HEAD request to pixel endpoint"
    )

    return Response(
        status_code=200,
        headers={
            "Content-Type": "image/gif",
            "Content-Length": str(len(TRANSPARENT_GIF))
        }
    )


@app.get("/click/{tracking_id}", response_class=HTMLResponse)
async def track_click_page(tracking_id: str, t: int, dest: str, request: Request):
    # Decode destination URL
    try:
        destination = base64.urlsafe_b64decode(dest.encode()).decode()
    except:
        destination = "https://example.com"  # Fallback

    # Capture request metadata for preliminary logging
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    current_time = int(time.time())

    # Preliminary analysis (without JS verification)
    verdict, reason = await analyze_request(
        ip=client_ip,
        user_agent=user_agent,
        method="GET",
        sent_timestamp=t,
        current_timestamp=current_time,
        tracking_id=tracking_id,
        has_js_verification=False  # Not yet - waiting for JS callback
    )

    # Log the initial click (will be updated after JS verification)
    await log_event(
        tracking_id=tracking_id,
        event_type="click_page_served",
        ip=client_ip,
        user_agent=user_agent,
        method="GET",
        verdict=verdict,
        reason=reason + " (preliminary - awaiting JS verification)"
    )

    # Serve the verification HTML page
    return templates.TemplateResponse("verification.html", {
        "request": request,
        "tracking_id": tracking_id,
        "destination": destination,
        "sent_timestamp": t
    })


@app.head("/click/{tracking_id}")
async def track_click_head(tracking_id: str, t: int, dest: str, request: Request):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    await log_event(
        tracking_id=tracking_id,
        event_type="click_head",
        ip=client_ip,
        user_agent=user_agent,
        method="HEAD",
        verdict="BOT",
        reason="HEAD request to click endpoint (link scanner behavior)"
    )

    return Response(status_code=200)


@app.post("/verify/{tracking_id}")
async def verify_human(tracking_id: str, request: Request):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    current_time = int(time.time())

    # Try to parse JSON body
    try:
        data = await request.json()
    except:
        # No valid JSON - likely a bot that doesn't properly execute JS
        await log_event(
            tracking_id=tracking_id,
            event_type="verify_failed",
            ip=client_ip,
            user_agent=user_agent,
            method="POST",
            verdict="BOT",
            reason="No verification data received (invalid JSON)"
        )
        return {"status": "ok"}

    # Extract verification data
    sent_timestamp = data.get("sentTimestamp", 0)
    mouse_movements = data.get("mouseMovements", [])
    fingerprint = data.get("fingerprint", {})
    js_executed = data.get("jsExecuted", False)

    # Run full analysis with JS verification data
    verdict, reason = await analyze_request(
        ip=client_ip,
        user_agent=user_agent,
        method="POST",
        sent_timestamp=sent_timestamp,
        current_timestamp=current_time,
        tracking_id=tracking_id,
        has_js_verification=True,
        mouse_movements=mouse_movements,
        fingerprint=fingerprint,
        js_executed=js_executed
    )

    # Log final verdict with all collected data
    await log_event(
        tracking_id=tracking_id,
        event_type="click_verified",
        ip=client_ip,
        user_agent=user_agent,
        method="POST",
        verdict=verdict,
        reason=reason,
        extra_data={
            "mouse_movement_count": len(mouse_movements),
            "fingerprint": fingerprint,
            "js_executed": js_executed
        }
    )

    return {"status": "ok", "verdict": verdict}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )
