import os
import sys
import json
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone, date, time as dtime
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  # no-op when .env is absent (e.g. GitHub Actions)

try:
    from zoneinfo import ZoneInfo
except ImportError:
    print("ERROR: zoneinfo not available. Use Python 3.9+.", file=sys.stderr)
    raise

API_URL = "https://eatery-blue-backend.cornellappdev.com/eatery/"
LOCAL_TZ = ZoneInfo("America/New_York")

CAMPUS_AREA_ALLOWLIST = {"West"}
EATERY_DENYLIST = {"104West!"}
PROMPT_PATH = "prompt.md"

# “Today” meal windows (local time). Adjust if desired.
MEAL_WINDOWS = {
    "breakfast_brunch": (dtime(6, 0), dtime(11, 0)),
    "lunch": (dtime(11, 0), dtime(16, 0)),
    "dinner": (dtime(16, 0), dtime(21, 0)),
}

# Map API event_description to our three buckets
EVENT_BUCKET = {
    "Breakfast": "breakfast_brunch",
    "Brunch": "breakfast_brunch",
    "Lunch": "lunch",
    "Late Lunch": "lunch",
    "Dinner": "dinner",
    "Late Night": "dinner",
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


def fetch_eateries() -> List[Dict[str, Any]]:
    r = requests.get(API_URL, timeout=25)
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        raise ValueError("API response is not a list.")
    return data


def epoch_to_local_dt(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(LOCAL_TZ)


def overlaps(
    a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime
) -> bool:
    return a_start < b_end and b_start < a_end


def flatten_menu(menu_obj: Any) -> Tuple[List[str], List[str]]:
    items: List[str] = []
    cats: List[str] = []

    if menu_obj is None:
        return items, cats

    if isinstance(menu_obj, list):
        for cat in menu_obj:
            if not isinstance(cat, dict):
                continue
            cat_name = cat.get("category")
            if isinstance(cat_name, str) and cat_name.strip():
                cats.append(cat_name.strip())
            its = cat.get("items", [])
            if isinstance(its, list):
                for it in its:
                    if isinstance(it, dict):
                        nm = it.get("name")
                        if isinstance(nm, str) and nm.strip():
                            items.append(nm.strip())
    elif isinstance(menu_obj, dict):
        # Some endpoints occasionally return dict-ish shapes.
        if "items" in menu_obj and isinstance(menu_obj.get("items"), list):
            cat_name = menu_obj.get("category")
            if isinstance(cat_name, str) and cat_name.strip():
                cats.append(cat_name.strip())
            for it in menu_obj["items"]:
                if isinstance(it, dict):
                    nm = it.get("name")
                    if isinstance(nm, str) and nm.strip():
                        items.append(nm.strip())
        else:
            nm = menu_obj.get("name")
            if isinstance(nm, str) and nm.strip():
                items.append(nm.strip())

    # Deduplicate while preserving order (lightweight)
    seen_i, seen_c = set(), set()
    out_i, out_c = [], []
    for x in items:
        if x not in seen_i:
            seen_i.add(x)
            out_i.append(x)
    for x in cats:
        if x not in seen_c:
            seen_c.add(x)
            out_c.append(x)
    return out_i, out_c


def build_today_windows(local_dt: datetime) -> Dict[str, Tuple[datetime, datetime]]:
    today = local_dt.date()
    windows: Dict[str, Tuple[datetime, datetime]] = {}
    for bucket, (t0, t1) in MEAL_WINDOWS.items():
        start = datetime.combine(today, t0, tzinfo=LOCAL_TZ)
        end = datetime.combine(today, t1, tzinfo=LOCAL_TZ)
        windows[bucket] = (start, end)
    return windows


def extract_menu_slices(
    eateries: List[Dict[str, Any]], local_dt: datetime
) -> Dict[str, List[MenuSlice]]:
    windows = build_today_windows(local_dt)
    by_bucket: Dict[str, List[MenuSlice]] = {k: [] for k in MEAL_WINDOWS.keys()}

    for e in eateries:
        try:
            if e.get("campus_area") not in CAMPUS_AREA_ALLOWLIST:
                continue
            if e.get("name") in EATERY_DENYLIST:
                continue

            name = e.get("name") or "Unknown"
            location = e.get("location") or ""
            menu_summary = (e.get("menu_summary") or "").strip()

            events = e.get("events", [])
            if not isinstance(events, list):
                continue

            # Accumulate per bucket per eatery
            acc: Dict[str, Dict[str, Any]] = {}
            for ev in events:
                if not isinstance(ev, dict):
                    continue

                desc = ev.get("event_description")
                if not isinstance(desc, str):
                    continue
                bucket = EVENT_BUCKET.get(desc.strip())
                if bucket not in MEAL_WINDOWS:
                    continue

                start = ev.get("start")
                end = ev.get("end")
                if not isinstance(start, int) or not isinstance(end, int):
                    continue

                ev_start = epoch_to_local_dt(start)
                ev_end = epoch_to_local_dt(end)

                w_start, w_end = windows[bucket]
                if not overlaps(ev_start, ev_end, w_start, w_end):
                    continue

                items, cats = flatten_menu(ev.get("menu"))

                if bucket not in acc:
                    acc[bucket] = {"descs": [], "items": [], "cats": []}
                acc[bucket]["descs"].append(desc.strip())
                acc[bucket]["items"].extend(items)
                acc[bucket]["cats"].extend(cats)

            for bucket, d in acc.items():
                # Deduplicate again at bucket level
                uniq_items = []
                seen = set()
                for x in d["items"]:
                    if x not in seen:
                        seen.add(x)
                        uniq_items.append(x)

                uniq_cats = []
                seen = set()
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
        except Exception:
            continue

    return by_bucket


def call_llm(prompt: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    client = OpenAI(
        api_key=os.environ["DEEPSEEK_API_KEY"],
        base_url="https://api.deepseek.com",
    )
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

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
    return json.loads(text)


def build_email(
    local_dt: datetime, result: Dict[str, Any], menus: Dict[str, List[MenuSlice]]
) -> Tuple[str, str]:
    date_str = local_dt.strftime("%a, %b %d, %Y")
    subject = f"West Campus Dining Picks — {date_str}"

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
        name = pick.get("eatery", "")
        why = pick.get("why", "")
        label = "#1 Pick" if rank == 0 else "#2 Pick"
        color = "#d35400" if rank == 0 else "#7f8c8d"
        location = loc.get(name, "")
        loc_line = f'<div style="color:#888;font-size:13px;">{location}</div>' if location else ""
        return (
            f'<div style="margin-bottom:10px;">'
            f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
            f'font-size:12px;font-weight:bold;">{label}</span> '
            f'<strong style="font-size:15px;">{name}</strong>'
            f'{loc_line}'
            f'<div style="color:#555;font-size:13px;margin-top:2px;">{why}</div>'
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
            for i, p in enumerate(picks[:2]):
                inner += _pick_html(i, p)
        sections_html += (
            f'<div style="margin-bottom:24px;">'
            f'<h2 style="margin:0 0 8px 0;font-size:18px;color:#2c3e50;'
            f'border-bottom:2px solid #e67e22;padding-bottom:4px;">{title}</h2>'
            f'{inner}'
            f'</div>'
        )

    html = (
        f'<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
        f'max-width:520px;margin:0 auto;padding:16px;">'
        f'<h1 style="font-size:22px;color:#2c3e50;margin:0 0 4px 0;">'
        f'West Campus Dining Picks</h1>'
        f'<p style="color:#888;font-size:13px;margin:0 0 20px 0;">'
        f'{date_str} &middot; {local_dt.strftime("%I:%M %p %Z").lstrip("0")}</p>'
        f'{sections_html}'
        f'<hr style="border:none;border-top:1px solid #eee;margin:20px 0 12px 0;">'
        f'<p style="font-size:11px;color:#aaa;">Data: Cornell AppDev Eatery API</p>'
        f'</div>'
    )
    return subject, html


def send_email(subject: str, body: str) -> None:
    gmail_user = os.environ.get("GMAIL_USER", "").strip()
    gmail_app_password = os.environ.get("GMAIL_APP_PASSWORD", "").strip()
    to_emails = [e.strip() for e in os.environ.get("TO_EMAIL", "").split(",") if e.strip()]

    if not gmail_user or not gmail_app_password or not to_emails:
        raise RuntimeError("Missing env vars: GMAIL_USER, GMAIL_APP_PASSWORD, TO_EMAIL")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = gmail_user
    msg["To"] = ", ".join(to_emails)
    msg.set_content("View this email in an HTML-capable client.")
    msg.add_alternative(body, subtype="html")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(gmail_user, gmail_app_password)
        smtp.send_message(msg)


def main() -> int:
    local_dt = datetime.now(LOCAL_TZ)

    prompt = load_prompt()
    eateries = fetch_eateries()
    menus = extract_menu_slices(eateries, local_dt)

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
    subject, body = build_email(local_dt, result, menus)
    send_email(subject, body)
    print("Email sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
