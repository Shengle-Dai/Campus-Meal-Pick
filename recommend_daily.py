import asyncio
import hashlib
import hmac
import os
import sys
import json
import re
import smtplib
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from html import escape
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

from dotenv import load_dotenv
from openai import OpenAI
from playwright.async_api import async_playwright

load_dotenv()  # no-op when .env is absent (e.g. GitHub Actions)

try:
    from zoneinfo import ZoneInfo
except ImportError:
    print("ERROR: zoneinfo not available. Use Python 3.9+.", file=sys.stderr)
    raise

LOCAL_TZ = ZoneInfo("America/New_York")

EATERY_DENYLIST = {"104West!"}
PROMPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompt.md")

# Map meal title (with " Menu" stripped) to our three buckets
EVENT_BUCKET = {
    "Breakfast": "breakfast_brunch",
    "Brunch": "breakfast_brunch",
    "Lunch": "lunch",
    "Late Lunch": "lunch",
    "Dinner": "dinner",
}


@dataclass
class MenuSlice:
    eatery_name: str
    location: str
    bucket: str
    event_descriptions: List[str]
    categories: List[str]
    items: List[str]
    menu_summary: str


def load_prompt() -> str:
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()


MEAL_BUCKETS = ("breakfast_brunch", "lunch", "dinner")


async def scrape_menus(local_dt: datetime) -> Dict[str, List[MenuSlice]]:
    by_bucket: Dict[str, List[MenuSlice]] = {k: [] for k in MEAL_BUCKETS}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("https://now.dining.cornell.edu/eateries", wait_until="networkidle")

        # Wait for cards to appear
        await page.wait_for_selector("app-card", timeout=15000)

        # Click the "West" campus tab
        west_tab = page.locator("text=West").first
        await west_tab.click()
        await page.wait_for_timeout(1500)

        cards = await page.locator("app-card").all()
        for card in cards:
            try:
                # Extract eatery name
                name_el = card.locator(".eateries-name a")
                name = (await name_el.text_content() or "").strip()
                if not name or name in EATERY_DENYLIST:
                    continue

                # Extract location
                location = ""
                loc_spans = card.locator(".eateries-name span")
                count = await loc_spans.count()
                if count > 0:
                    location = (await loc_spans.last.text_content() or "").strip()

                # Extract description (menu_summary)
                menu_summary = ""
                about_el = card.locator(".eateries-about-short")
                if await about_el.count() > 0:
                    menu_summary = (await about_el.first.text_content() or "").strip()

                # Check for mat-expansion-panel menus (skip non-dining eateries)
                panels = await card.locator("mat-expansion-panel").all()
                if not panels:
                    continue

                # Accumulate per bucket
                acc: Dict[str, Dict[str, Any]] = {}

                for panel in panels:
                    # Extract meal name from panel title
                    title_el = panel.locator("mat-panel-title")
                    title_text = (await title_el.text_content() or "").strip()
                    # Strip " Menu" suffix: "Breakfast Menu" -> "Breakfast"
                    meal_name = re.sub(r"\s*Menu\s*$", "", title_text).strip()

                    bucket = EVENT_BUCKET.get(meal_name)
                    if not bucket:
                        continue

                    # Expand the panel if not already expanded
                    panel_classes = await panel.get_attribute("class") or ""
                    if "mat-expanded" not in panel_classes:
                        await panel.click()
                        await page.wait_for_timeout(300)

                    # Extract categories
                    cat_els = await panel.locator(".eateries-menu-category").all()
                    cats = []
                    for cel in cat_els:
                        ct = (await cel.text_content() or "").strip()
                        if ct:
                            cats.append(ct)

                    # Extract items (separated by " • ")
                    item_els = await panel.locator(".eateries-menu-items").all()
                    items = []
                    for iel in item_els:
                        raw = (await iel.text_content() or "").strip()
                        if raw:
                            for part in raw.split(" • "):
                                part = part.strip()
                                if part:
                                    items.append(part)

                    if bucket not in acc:
                        acc[bucket] = {"descs": [], "items": [], "cats": []}
                    acc[bucket]["descs"].append(meal_name)
                    acc[bucket]["items"].extend(items)
                    acc[bucket]["cats"].extend(cats)

                for bucket, d in acc.items():
                    # Deduplicate while preserving order
                    seen = set()
                    uniq_items = []
                    for x in d["items"]:
                        if x not in seen:
                            seen.add(x)
                            uniq_items.append(x)

                    seen = set()
                    uniq_cats = []
                    for x in d["cats"]:
                        if x not in seen:
                            seen.add(x)
                            uniq_cats.append(x)

                    if not uniq_items and not uniq_cats:
                        continue

                    by_bucket[bucket].append(
                        MenuSlice(
                            eatery_name=name,
                            location=location,
                            bucket=bucket,
                            event_descriptions=sorted(set(d["descs"])),
                            categories=uniq_cats[:40],
                            items=uniq_items[:120],
                            menu_summary=menu_summary,
                        )
                    )
            except Exception as e:
                print(f"WARNING: skipped card: {e}", file=sys.stderr)
                continue

        await browser.close()

    return by_bucket


def call_llm(prompt: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    client = OpenAI(
        api_key=os.environ["GROQ_API_KEY"],
        base_url="https://api.groq.com/openai/v1/",
    )
    model = os.environ.get("GROQ_MODEL", "").strip() or "openai/gpt-oss-120b"

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": prompt},
            {
                "role": "user",
                "content": f"Choose winners for today. Data:\n{json.dumps(payload, ensure_ascii=False)}",
            },
        ],
        response_format={"type": "json_object"},
    )

    text = resp.choices[0].message.content
    if not text:
        raise RuntimeError("LLM returned empty response")
    return json.loads(text)


def sanitize_result(
    result: Any, menus: Dict[str, List[MenuSlice]]
) -> Dict[str, Any]:
    """Validate and fix LLM output: enforce structure, dedupe eateries, cap picks."""
    if not isinstance(result, dict):
        result = {}

    valid_eateries: Dict[str, set] = {}
    for bucket, slices in menus.items():
        valid_eateries[bucket] = {ms.eatery_name for ms in slices}

    for bucket in MEAL_BUCKETS:
        meal = result.get(bucket)
        if not isinstance(meal, dict):
            result[bucket] = {"picks": []}
            continue

        picks = meal.get("picks")
        if not isinstance(picks, list):
            meal["picks"] = []
            continue

        # Deduplicate eateries and ensure each pick has required fields
        seen: set = set()
        clean: list = []
        for p in picks:
            if not isinstance(p, dict):
                continue
            eatery = p.get("eatery", "")
            if not isinstance(eatery, str) or not eatery:
                continue
            if eatery in seen:
                continue
            seen.add(eatery)
            dishes = p.get("dishes", [])
            if not isinstance(dishes, list):
                dishes = []
            clean.append({"eatery": eatery, "dishes": [str(d) for d in dishes]})

        meal["picks"] = clean[:3]

    return result


def generate_unsub_token(email: str, secret: str) -> str:
    """Generate an HMAC-SHA256 token for unsubscribe links."""
    return hmac.new(secret.encode(), email.lower().encode(), hashlib.sha256).hexdigest()


def fetch_subscribers_from_kv() -> List[str]:
    """Fetch confirmed subscriber emails from Cloudflare Workers KV.

    Requires WORKER_BASE_URL and HMAC_SECRET env vars.
    Returns empty list if not configured (falls back to TO_EMAIL).
    """
    worker_url = os.environ.get("WORKER_BASE_URL", "").strip().rstrip("/")
    hmac_secret = os.environ.get("HMAC_SECRET", "").strip()

    if not worker_url or not hmac_secret:
        return []

    import urllib.request

    req = urllib.request.Request(
        f"{worker_url}/api/subscribers",
        headers={
            "Authorization": f"Bearer {hmac_secret}",
            "User-Agent": "CampusMealPick-Daily/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("subscribers", [])
    except Exception as e:
        print(f"WARNING: failed to fetch subscribers from KV: {e}", file=sys.stderr)
        return []


def build_email(
    local_dt: datetime,
    result: Dict[str, Any],
    menus: Dict[str, List[MenuSlice]],
    unsubscribe_url: str = "",
) -> Tuple[str, str]:
    date_str = local_dt.strftime("%a, %b %d, %Y")
    subject = f"CMP — West Campus Dining Picks — {date_str}"

    # Location lookup
    loc: Dict[str, str] = {}
    for bucket, lst in menus.items():
        for ms in lst:
            loc[ms.eatery_name] = ms.location

    meal_labels = [
        ("Breakfast / Brunch", "breakfast_brunch"),
        ("Lunch", "lunch"),
        ("Dinner", "dinner"),
    ]

    def _pick_html(rank: int, pick: Dict[str, Any]) -> str:
        raw_name = pick.get("eatery", "")
        name = escape(raw_name)
        dishes = pick.get("dishes", [])
        labels = {0: "#1 Pick", 1: "#2 Pick", 2: "#3 Pick"}
        colors = {0: "#d35400", 1: "#7f8c8d", 2: "#7f8c8d"}
        label = labels.get(rank, f"#{rank+1} Pick")
        color = colors.get(rank, "#7f8c8d")
        location = escape(loc.get(raw_name, ""))
        loc_line = f'<div style="color:#888;font-size:13px;">{location}</div>' if location else ""
        dishes_line = ""
        if dishes:
            items_html = "".join(f"<li>{escape(d)}</li>" for d in dishes)
            dishes_line = f'<ul style="color:#555;font-size:13px;margin:4px 0 0 0;padding-left:20px;">{items_html}</ul>'
        return (
            f'<div style="margin-bottom:10px;">'
            f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
            f'font-size:12px;font-weight:bold;">{label}</span> '
            f'<strong style="font-size:15px;">{name}</strong>'
            f'{loc_line}'
            f'{dishes_line}'
            f'</div>'
        )

    sections_html = ""
    for title, key in meal_labels:
        obj = result.get(key, {}) if isinstance(result, dict) else {}
        picks = obj.get("picks", [])
        inner = ""
        if not picks:
            inner = '<p style="color:#999;">No recommendation (no matching menu found).</p>'
        else:
            for i, p in enumerate(picks[:3]):
                inner += _pick_html(i, p)
        sections_html += (
            f'<div style="margin-bottom:24px;">'
            f'<h2 style="margin:0 0 8px 0;font-size:18px;color:#2c3e50;'
            f'border-bottom:2px solid #e67e22;padding-bottom:4px;">{title}</h2>'
            f'{inner}'
            f'</div>'
        )

    # Unsubscribe footer
    unsub_line = ""
    if unsubscribe_url:
        unsub_line = (
            f'<p style="font-size:11px;color:#aaa;margin-top:8px;">'
            f'<a href="{escape(unsubscribe_url)}" style="color:#aaa;">'
            f'Unsubscribe from daily picks</a></p>'
        )

    html = (
        f'<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
        f'max-width:520px;margin:0 auto;padding:16px;">'
        f'<h1 style="font-size:22px;color:#2c3e50;margin:0 0 4px 0;">'
        f'Campus Meal Pick</h1>'
        f'<p style="color:#888;font-size:13px;margin:0 0 20px 0;">'
        f'{date_str} &middot; {local_dt.strftime("%I:%M %p %Z").lstrip("0")}</p>'
        f'{sections_html}'
        f'<hr style="border:none;border-top:1px solid #eee;margin:20px 0 12px 0;">'
        f'<p style="font-size:11px;color:#aaa;">Data: now.dining.cornell.edu</p>'
        f'{unsub_line}'
        f'</div>'
    )
    return subject, html


def send_emails(
    subject: str,
    result: Dict[str, Any],
    menus: Dict[str, List[MenuSlice]],
    local_dt: datetime,
) -> None:
    """Send individual emails with personalized unsubscribe links.

    Tries Cloudflare KV subscribers first; falls back to TO_EMAIL env var.
    """
    gmail_user = os.environ.get("GMAIL_USER", "").strip()
    gmail_app_password = os.environ.get("GMAIL_APP_PASSWORD", "").strip()
    hmac_secret = os.environ.get("HMAC_SECRET", "").strip()
    worker_url = os.environ.get("WORKER_BASE_URL", "").strip().rstrip("/")

    if not gmail_user or not gmail_app_password:
        raise RuntimeError("Missing env vars: GMAIL_USER, GMAIL_APP_PASSWORD")

    # Try KV subscribers first, fall back to TO_EMAIL
    kv_subscribers = fetch_subscribers_from_kv()
    if kv_subscribers:
        to_emails = kv_subscribers
        print(f"Sending to {len(to_emails)} KV subscriber(s).")
    else:
        to_emails = [
            e.strip()
            for e in os.environ.get("TO_EMAIL", "").split(",")
            if e.strip()
        ]
        print(f"KV not configured; falling back to TO_EMAIL ({len(to_emails)} recipient(s)).")

    if not to_emails:
        raise RuntimeError("No subscribers found (KV empty and TO_EMAIL not set)")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(gmail_user, gmail_app_password)

        for recipient in to_emails:
            # Build personalized unsubscribe URL
            unsub_url = ""
            if hmac_secret and worker_url:
                token = generate_unsub_token(recipient, hmac_secret)
                unsub_url = (
                    f"{worker_url}/api/unsubscribe"
                    f"?email={quote(recipient)}&token={token}"
                )

            _, body = build_email(local_dt, result, menus, unsub_url)

            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = gmail_user
            msg["To"] = recipient
            msg.set_content("View this email in an HTML-capable client.")
            msg.add_alternative(body, subtype="html")

            smtp.send_message(msg)
            print(f"  → Sent to {recipient}")


def store_daily_picks(
    result: Dict[str, Any],
    menus: Dict[str, List[MenuSlice]],
    local_dt: datetime,
) -> None:
    """Store daily picks in Cloudflare KV via Worker API."""
    worker_url = os.environ.get("WORKER_BASE_URL", "").strip().rstrip("/")
    hmac_secret = os.environ.get("HMAC_SECRET", "").strip()

    if not worker_url or not hmac_secret:
        print("WARNING: WORKER_BASE_URL or HMAC_SECRET not set; skipping KV store.", file=sys.stderr)
        return

    # Build location map
    loc_map = {}
    for bucket, lst in menus.items():
        for ms in lst:
            loc_map[ms.eatery_name] = ms.location

    payload = {
        "date_str": local_dt.strftime("%a, %b %d"),
        "meals": result,
        "location_map": loc_map,
    }

    import urllib.request

    req = urllib.request.Request(
        f"{worker_url}/api/store_picks",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {hmac_secret}",
            "User-Agent": "CampusMealPick-Daily/1.0",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                print("Successfully stored daily picks in KV.")
            else:
                print(f"WARNING: Worker returned status {resp.status} for store_picks.", file=sys.stderr)
    except Exception as e:
        print(f"WARNING: failed to store picks in KV: {e}", file=sys.stderr)


async def main() -> int:
    local_dt = datetime.now(LOCAL_TZ)

    prompt = load_prompt()
    menus = await scrape_menus(local_dt)

    payload = {
        "date_local": local_dt.strftime("%Y-%m-%d"),
        "timezone": "America/New_York",
        "campus_area_filter": "West",
        "meals": {
            k: [
                {
                    "eatery_name": ms.eatery_name,
                    "location": ms.location,
                    "event_descriptions": ms.event_descriptions,
                    "menu_summary": ms.menu_summary,
                    "categories": ms.categories,
                    "items": ms.items,
                }
                for ms in v
            ]
            for k, v in menus.items()
        },
    }

    result = call_llm(prompt, payload)
    result = sanitize_result(result, menus)
    subject, _ = build_email(local_dt, result, menus)
    store_daily_picks(result, menus, local_dt)
    send_emails(subject, result, menus, local_dt)
    print("All emails sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
