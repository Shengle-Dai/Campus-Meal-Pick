/**
 * Campus Meal Pick (CMP) Subscribe/Unsubscribe Worker
 *
 * Endpoints:
 *   GET  /                     — Subscribe form (renders daily picks if available)
 *   POST /api/subscribe        — Start subscribe flow (triggers verification email)
 *   GET  /api/confirm          — Confirm subscription (verifies HMAC token)
 *   GET  /api/unsubscribe      — Remove subscription (verifies HMAC token)
 *   GET  /api/subscribers      — List confirmed subscribers (internal, requires auth)
 *   POST /api/store_picks      — Store daily picks JSON (internal, requires auth)
 *
 * KV keys: 
 *   "sub:<email>" → JSON { subscribedAt }
 *   "latest_picks" → JSON { date_str, meals, location_map }
 *
 * Secrets: HMAC_SECRET, GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO
 */

// ─── Crypto helpers ─────────────────────────────────────────────────────────

async function hmacSign(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacVerify(secret, data, token) {
  const expected = await hmacSign(secret, data);
  // Constant-time comparison
  if (expected.length !== token.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ token.charCodeAt(i);
  }
  return diff === 0;
}

// ─── HTML templates ─────────────────────────────────────────────────────────

function pageShell(title, content) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    :root { --cornell-red: #B31B1B; --text: #222; --text-light: #555; --bg: #ffffff; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }
    .container {
      max-width: 400px;
      width: 100%;
      text-align: center;
    }
    h1 {
      font-family: "Palatino Linotype", "Book Antiqua", Palatino, serif; /* Cornell-esque serif */
      color: var(--cornell-red);
      font-size: 24px;
      font-weight: 600;
      margin: 0 0 16px;
      letter-spacing: -0.01em;
    }
    p {
      color: var(--text-light);
      font-size: 16px;
      line-height: 1.5;
      margin: 0 0 32px;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    input {
      width: 100%;
      padding: 12px 0;
      border: none;
      border-bottom: 2px solid #eee;
      font-size: 16px;
      outline: none;
      border-radius: 0;
      background: transparent;
      text-align: center;
      transition: border-color 0.2s;
      color: var(--text);
    }
    input:focus {
      border-bottom-color: var(--cornell-red);
    }
    input::placeholder {
      color: #aaa;
    }
    button {
      width: 100%;
      padding: 14px;
      margin-top: 10px;
      background: transparent;
      color: var(--cornell-red);
      border: 1px solid var(--cornell-red);
      border-radius: 4px;
      font-size: 14px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      cursor: pointer;
      transition: all 0.2s;
    }
    button:hover {
      background: var(--cornell-red);
      color: white;
    }
    .icon {
      margin-bottom: 24px;
      color: var(--cornell-red);
    }
    .icon svg {
      width: 32px;
      height: 32px;
    }
    .footer {
      margin-top: 40px;
      font-size: 12px;
      color: #999;
      font-family: "Palatino Linotype", "Book Antiqua", Palatino, serif;
      font-style: italic;
    }
    a { color: var(--cornell-red); text-decoration: none; }
    a:hover { text-decoration: underline; }

    .how-it-works {
      margin-top: 60px;
      padding-top: 40px;
      border-top: 1px solid #eaeaea;
      display: flex;
      justify-content: center;
      gap: 40px;
      flex-wrap: wrap;
    }
    .step {
      flex: 1;
      min-width: 120px;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      opacity: 0;
      animation: fadeUp 1s cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
    }
    .step:nth-child(1) { animation-delay: 0.2s; }
    .step:nth-child(2) { animation-delay: 0.4s; }
    .step:nth-child(3) { animation-delay: 0.6s; }
    
    .step-icon {
      width: 56px;
      height: 56px;
      color: var(--cornell-red);
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 20px;
      transition: transform 0.4s ease;
    }
    .step:hover .step-icon {
      transform: translateY(-5px);
    }
    .step-icon svg {
      width: 32px;
      height: 32px;
      stroke-width: 1;
    }

    .step h3 {
      font-family: "Palatino Linotype", "Book Antiqua", Palatino, serif;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-weight: 600;
      color: var(--text);
      margin: 0 0 8px;
    }
    .step p {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      color: #777;
      margin: 0;
      max-width: 160px;
    }
    
    /* Email Sample Preview */
    .email-preview {
      margin-top: 60px;
      padding: 0 20px;
      animation: fadeUp 1s cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
      animation-delay: 0.8s;
      opacity: 0;
      width: 100%;
      max-width: 480px;
      box-sizing: border-box;
    }
    .email-card {
      border: 1px solid #eaeaea;
      background: #fafafa;
      padding: 32px;
      text-align: left;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .email-meta {
      font-size: 11px;
      color: #999;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid #eee;
      display: flex;
      justify-content: space-between;
    }
    .meal-section {
      margin-bottom: 24px;
    }
    .meal-title {
      font-family: "Palatino Linotype", "Book Antiqua", Palatino, serif;
      font-size: 18px;
      color: var(--cornell-red);
      margin: 0 0 16px;
      font-weight: 600;
      letter-spacing: -0.01em;
      border-bottom: 1px solid #e67e22;
      padding-bottom: 4px;
      display: inline-block;
    }
    .pick-item {
      margin-bottom: 16px;
      page-break-inside: avoid;
    }
    .pick-header {
      font-size: 13px;
      font-weight: 600;
      color: var(--text);
      margin: 0 0 4px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .pick-rank {
      font-size: 11px;
      color: #fff;
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: bold;
    }
    /* Rank colors matching email */
    .rank-0 { background-color: #d35400; }
    .rank-1 { background-color: #7f8c8d; }
    .rank-2 { background-color: #7f8c8d; }
    
    .pick-location {
      font-size: 12px;
      color: #888;
      font-weight: normal;
      margin-left: auto;
    }
    .pick-menu {
      font-size: 13px;
      color: #555;
      line-height: 1.4;
      margin: 4px 0 0 0;
      padding-left: 20px;
      list-style: disc;
    }
    .pick-menu li {
      margin-bottom: 2px;
    }
    
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="container">${content}</div>
</body>
</html>`;
}

const icons = {
  // Minimalist icons
  email: `<div class="icon"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg></div>`,
  success: `<div class="icon"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 13l4 4L19 7" /></svg></div>`,
  error: `<div class="icon"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12" /></svg></div>`,
  info: `<div class="icon"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg></div>`
};

function renderPicksHtml(picksData) {
  if (!picksData) return "";

  const { date_str, meals, location_map } = picksData;
  // expects structure:
  // {
  //   date_str: "Fri, Feb 13",
  //   meals: {
  //     "breakfast_brunch": { picks: [...] },
  //     "lunch": { picks: [...] },
  //     "dinner": { picks: [...] }
  //   },
  //   location_map: { "Eatery Name": "Location" }
  // }

  const mealLabels = [
    { key: "breakfast_brunch", title: "Breakfast / Brunch" },
    { key: "lunch", title: "Lunch" },
    { key: "dinner", title: "Dinner" },
  ];

  let sectionsHtml = "";

  for (const { key, title } of mealLabels) {
    const mealObj = meals && meals[key] ? meals[key] : {};
    const picks = mealObj.picks || [];

    if (picks.length === 0) continue;

    let itemsHtml = "";
    picks.slice(0, 3).forEach((pick, index) => {
      const rank = index + 1;
      const dishes = pick.dishes || [];
      const eatery = pick.eatery || "";
      const location = (location_map && location_map[eatery]) || "";
      
      const dishesList = dishes.map(d => `<li>${d}</li>`).join("");
      
      itemsHtml += `
        <div class="pick-item">
          <div class="pick-header">
            <span class="pick-rank rank-${index}">#${rank} Pick</span>
            <strong>${eatery}</strong>
            ${location ? `<span class="pick-location">${location}</span>` : ""}
          </div>
          <ul class="pick-menu">
            ${dishesList}
          </ul>
        </div>
      `;
    });

    sectionsHtml += `
      <div class="meal-section">
        <h2 class="meal-title">${title}</h2>
        ${itemsHtml}
      </div>
    `;
  }

  if (!sectionsHtml) return "";

  return `
    <div class="email-preview">
      <div class="email-card">
        <div class="email-meta">
          <span>${date_str || "Recently"}</span>
          <span>Sample Email</span>
        </div>
        ${sectionsHtml}
      </div>
    </div>
  `;
}

function subscribePage(picksData) {
  const picksHtml = renderPicksHtml(picksData);

  return pageShell(
    "Campus Meal Pick",
    `
    <h1>Daily Dining Picks</h1>
    <p>Curated recommendations for West Campus.</p>
    <form method="POST" action="/api/subscribe">
      <input type="email" name="email" placeholder="netid@cornell.edu" required aria-label="Email address" autocomplete="email">
      <button type="submit">Subscribe</button>
    </form>
    <div class="footer">Verification email will be sent.</div>

    <div class="how-it-works">
      <div class="step">
        <div class="step-icon">
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
        </div>
        <h3>Menu Scrape</h3>
        <p>Daily menus from West Campus dining halls.</p>
      </div>
      
      <div class="step">
        <div class="step-icon">
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
          </svg>
        </div>
        <h3>AI Curates</h3>
        <p>Top 3 picks based on variety &amp; nutrition.</p>
      </div>

      <div class="step">
        <div class="step-icon">
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        </div>
        <h3>You Eat</h3>
        <p>A clean daily email. No spam, just food.</p>
      </div>
    </div>

    ${picksHtml}
    `
  );
}

function resultPage(type, title, message) {
  const icon = icons[type] || icons.info;
  return pageShell(
    title,
    `
    ${icon}
    <h1>${title}</h1>
    <p>${message}</p>
    `
  );
}

// ─── Handlers ───────────────────────────────────────────────────────────────

async function handleSubscribe(request, env) {
  const contentType = request.headers.get("content-type") || "";
  let email = "";

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const form = await request.formData();
    email = (form.get("email") || "").toString().trim().toLowerCase();
  } else if (contentType.includes("application/json")) {
    const body = await request.json();
    email = (body.email || "").toString().trim().toLowerCase();
  }

  // Basic validation
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return new Response(
      resultPage("error", "Invalid Email", "Please enter a valid email address."),
      { status: 400, headers: { "Content-Type": "text/html" } }
    );
  }

  // Check if already subscribed
  const existing = await env.SUBSCRIBERS.get(`sub:${email}`);
  if (existing) {
    return new Response(
      resultPage("info", "Already Subscribed", "This email is already receiving daily dining picks!"),
      { headers: { "Content-Type": "text/html" } }
    );
  }

  // Generate HMAC token
  const token = await hmacSign(env.HMAC_SECRET, email);
  const workerUrl = new URL(request.url).origin;
  const confirmUrl = `${workerUrl}/api/confirm?email=${encodeURIComponent(email)}&token=${token}`;

  // Trigger GitHub Actions to send verification email
  const dispatchRes = await fetch(
    `https://api.github.com/repos/${env.GH_OWNER}/${env.GH_REPO}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GH_PAT_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "campus-meal-pick-worker",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        event_type: "send_verification",
        client_payload: {
          email: email,
          confirm_url: confirmUrl,
        },
      }),
    }
  );

  if (!dispatchRes.ok) {
    const errText = await dispatchRes.text();
    console.error("GitHub dispatch failed:", dispatchRes.status, errText);
    return new Response(
      resultPage("error", "Something Went Wrong", "Failed to send verification email. Please try again later."),
      { status: 500, headers: { "Content-Type": "text/html" } }
    );
  }

  return new Response(
    resultPage(
      "email",
      "Check Your Inbox",
      `We've sent a confirmation email to <strong>${email}</strong>. Click the link inside to activate your subscription. (It may take up to a minute to arrive.)`
    ),
    { headers: { "Content-Type": "text/html" } }
  );
}

async function handleConfirm(request, env) {
  const url = new URL(request.url);
  const email = (url.searchParams.get("email") || "").trim().toLowerCase();
  const token = url.searchParams.get("token") || "";

  if (!email || !token) {
    return new Response(
      resultPage("error", "Invalid Link", "This confirmation link is invalid."),
      { status: 400, headers: { "Content-Type": "text/html" } }
    );
  }

  const valid = await hmacVerify(env.HMAC_SECRET, email, token);
  if (!valid) {
    return new Response(
      resultPage("error", "Invalid Token", "This confirmation link is invalid or has been tampered with."),
      { status: 403, headers: { "Content-Type": "text/html" } }
    );
  }

  // Check if already subscribed
  const existing = await env.SUBSCRIBERS.get(`sub:${email}`);
  if (existing) {
    return new Response(
      resultPage("info", "Already Subscribed", "You're already subscribed! Daily picks are on their way."),
      { headers: { "Content-Type": "text/html" } }
    );
  }

  // Add to KV
  await env.SUBSCRIBERS.put(
    `sub:${email}`,
    JSON.stringify({ subscribedAt: new Date().toISOString() })
  );

  return new Response(
    resultPage(
      "success",
      "You're Subscribed!",
      "You'll start receiving daily West Campus dining recommendations. Welcome aboard!"
    ),
    { headers: { "Content-Type": "text/html" } }
  );
}

async function handleUnsubscribe(request, env) {
  const url = new URL(request.url);
  const email = (url.searchParams.get("email") || "").trim().toLowerCase();
  const token = url.searchParams.get("token") || "";

  if (!email || !token) {
    return new Response(
      resultPage("error", "Invalid Link", "This unsubscribe link is invalid."),
      { status: 400, headers: { "Content-Type": "text/html" } }
    );
  }

  const valid = await hmacVerify(env.HMAC_SECRET, email, token);
  if (!valid) {
    return new Response(
      resultPage("error", "Invalid Token", "This unsubscribe link is invalid or has been tampered with."),
      { status: 403, headers: { "Content-Type": "text/html" } }
    );
  }

  // Remove from KV
  await env.SUBSCRIBERS.delete(`sub:${email}`);

  return new Response(
    resultPage(
      "success",
      "Unsubscribed",
      "You've been removed from the daily dining picks. You can re-subscribe anytime!"
    ),
    { headers: { "Content-Type": "text/html" } }
  );
}

async function handleListSubscribers(request, env) {
  // Protected endpoint — only callable from GitHub Actions with the correct token
  const authHeader = request.headers.get("Authorization") || "";
  const expected = `Bearer ${env.HMAC_SECRET}`;
  if (authHeader !== expected) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const subscribers = [];
  let cursor = null;

  do {
    const result = await env.SUBSCRIBERS.list({
      prefix: "sub:",
      cursor: cursor,
      limit: 1000,
    });
    for (const key of result.keys) {
      // Key name is "sub:email@example.com"
      subscribers.push(key.name.slice(4));
    }
    cursor = result.list_complete ? null : result.cursor;
  } while (cursor);

  return Response.json({ subscribers });
}

async function handleStorePicks(request, env) {
  // Protected endpoint to store daily picks JSON
  const authHeader = request.headers.get("Authorization") || "";
  const expected = `Bearer ${env.HMAC_SECRET}`;
  if (authHeader !== expected) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const picks = await request.json();
    if (!picks || !picks.date_str || !picks.meals) {
        return Response.json({ error: "Invalid payload structure" }, { status: 400 });
    }

    // cache for 24 hours (86400 seconds) or indefinite
    // We'll just put it in KV.
    await env.SUBSCRIBERS.put("latest_picks", JSON.stringify(picks));
    
    return Response.json({ success: true, stored_date: picks.date_str });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── Router ─────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers for API endpoints
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      if (path === "/" && request.method === "GET") {
        // Try to fetch latest picks to render the preview
        let picks = null;
        try {
          picks = await env.SUBSCRIBERS.get("latest_picks", { type: "json" });
        } catch (e) {
          console.error("Failed to load picks:", e);
        }

        return new Response(subscribePage(picks), {
          headers: { "Content-Type": "text/html" },
        });
      }

      if (path === "/api/subscribe" && request.method === "POST") {
        return await handleSubscribe(request, env);
      }

      if (path === "/api/confirm" && request.method === "GET") {
        return await handleConfirm(request, env);
      }

      if (path === "/api/unsubscribe" && request.method === "GET") {
        return await handleUnsubscribe(request, env);
      }

      if (path === "/api/subscribers" && request.method === "GET") {
        return await handleListSubscribers(request, env);
      }

      if (path === "/api/store_picks" && request.method === "POST") {
        return await handleStorePicks(request, env);
      }

      return new Response("Not Found", { status: 404 });
    } catch (err) {
      console.error("Worker error:", err);
      return new Response(
        resultPage("error", "Error", "Something went wrong. Please try again."),
        { status: 500, headers: { "Content-Type": "text/html" } }
      );
    }
  },
};
