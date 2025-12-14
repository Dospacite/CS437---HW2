
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

# These are partial ranges for major cloud providers
# Requests from these IPs are likely automated scanners

DATACENTER_CIDRS = [
    # Amazon AWS (partial list of common ranges)
    "3.0.0.0/8",
    "13.32.0.0/12",
    "13.48.0.0/13",
    "13.56.0.0/14",
    "18.0.0.0/8",
    "34.192.0.0/10",
    "35.152.0.0/13",
    "52.0.0.0/8",
    "54.0.0.0/8",
    "99.77.0.0/16",

    # Microsoft Azure (partial list)
    "13.64.0.0/11",
    "13.96.0.0/13",
    "13.104.0.0/14",
    "20.0.0.0/8",
    "40.64.0.0/10",
    "51.104.0.0/14",
    "52.224.0.0/11",
    "104.40.0.0/13",
    "137.116.0.0/15",
    "168.61.0.0/16",

    # Google Cloud Platform (partial list)
    "34.64.0.0/10",
    "35.184.0.0/13",
    "35.192.0.0/12",
    "35.208.0.0/12",
    "35.224.0.0/12",
    "35.240.0.0/13",
    "104.154.0.0/15",
    "104.196.0.0/14",
    "130.211.0.0/16",
    "146.148.0.0/17",

    # DigitalOcean (partial list)
    "104.131.0.0/16",
    "104.236.0.0/16",
    "107.170.0.0/16",
    "138.68.0.0/16",
    "139.59.0.0/16",
    "159.65.0.0/16",
    "159.89.0.0/16",
    "161.35.0.0/16",
    "162.243.0.0/16",
    "164.90.0.0/16",
    "165.22.0.0/16",
    "167.99.0.0/16",
    "178.62.0.0/16",
    "188.166.0.0/16",

    # Linode (partial list)
    "45.33.0.0/16",
    "45.56.0.0/16",
    "45.79.0.0/16",
    "50.116.0.0/16",
    "66.175.208.0/20",
    "69.164.192.0/18",
    "72.14.176.0/20",
    "74.207.224.0/19",
    "96.126.96.0/19",
    "97.107.128.0/17",
    "139.162.0.0/16",
    "172.104.0.0/15",
    "173.230.128.0/17",
    "173.255.192.0/18",
    "192.155.80.0/20",
    "198.58.96.0/19",
    "198.74.48.0/20",

    # Vultr (partial list)
    "45.32.0.0/15",
    "45.63.0.0/16",
    "45.76.0.0/15",
    "64.156.0.0/16",
    "64.237.32.0/19",
    "66.42.32.0/19",
    "104.156.224.0/19",
    "108.61.0.0/16",
    "136.244.64.0/18",
    "140.82.0.0/16",
    "149.28.0.0/16",
    "155.138.128.0/17",
    "207.148.0.0/17",
    "209.222.0.0/18",
    "216.128.128.0/17",

    # OVH (partial list)
    "51.38.0.0/15",
    "51.68.0.0/15",
    "51.75.0.0/16",
    "51.77.0.0/16",
    "51.79.0.0/16",
    "51.81.0.0/16",
    "51.83.0.0/16",
    "51.89.0.0/16",
    "51.91.0.0/16",
    "54.36.0.0/14",
    "54.37.0.0/16",
    "54.38.0.0/16",
    "135.125.0.0/16",
    "141.94.0.0/15",
    "145.239.0.0/16",
    "146.59.0.0/16",
    "147.135.0.0/16",
    "149.202.0.0/16",
    "151.80.0.0/16",
    "158.69.0.0/16",
    "164.132.0.0/16",
    "167.114.0.0/16",
    "176.31.0.0/16",
    "178.32.0.0/15",
    "185.228.0.0/16",
    "188.165.0.0/16",
    "192.95.0.0/16",
    "192.99.0.0/16",
    "193.70.0.0/16",
    "198.27.64.0/18",
    "198.100.144.0/20",
    "198.245.48.0/20",

    # Hetzner (partial list)
    "5.9.0.0/16",
    "23.88.0.0/15",
    "46.4.0.0/16",
    "78.46.0.0/15",
    "88.198.0.0/16",
    "88.99.0.0/16",
    "94.130.0.0/16",
    "95.216.0.0/15",
    "116.202.0.0/15",
    "116.203.0.0/16",
    "128.140.0.0/16",
    "135.181.0.0/16",
    "136.243.0.0/16",
    "138.201.0.0/16",
    "142.132.128.0/17",
    "144.76.0.0/16",
    "148.251.0.0/16",
    "157.90.0.0/16",
    "159.69.0.0/16",
    "162.55.0.0/16",
    "167.235.0.0/16",
    "168.119.0.0/16",
    "176.9.0.0/16",
    "178.63.0.0/16",
    "188.40.0.0/16",
    "195.201.0.0/16",
    "213.133.96.0/19",
    "213.239.192.0/18",
]

# Pre-compile IP networks for efficient lookup
DATACENTER_NETWORKS = []
for cidr in DATACENTER_CIDRS:
    try:
        DATACENTER_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        pass  # Skip invalid CIDRs

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

    return {
        "tracking_id": tracking_id,
        "sent_timestamp": sent_timestamp,
        "sent_time_human": datetime.fromtimestamp(sent_timestamp).isoformat(),
        "pixel_url": f"{base_url}/pixel/{tracking_id}?t={sent_timestamp}",
        "click_url": f"{base_url}/click/{tracking_id}?t={sent_timestamp}&dest={encoded_dest}",
        "destination": dest,
        "usage": {
            "pixel": "Embed as <img> tag in email to track opens",
            "click": "Use as href in links to track clicks"
        }
    }


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
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
