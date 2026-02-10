# Cornell Dining Selection

Automated daily AI-powered dining recommendations (top 3 picks per meal) from Cornell West Campus eateries, delivered via email.

## How it works

1. **Scrape** — Launches headless Chromium via Playwright, navigates to `now.dining.cornell.edu/eateries`, clicks the "West" campus tab, and extracts each dining hall's meal menus (categories + individual dishes)
2. **Analyze** — Sends the scraped menu data to DeepSeek LLM with a customizable system prompt (`prompt.md`) that encodes food preferences and decision rules
3. **Rank** — LLM returns JSON with top 3 eatery picks per meal (breakfast/brunch, lunch, dinner), each with recommended dishes
4. **Email** — Formats the picks into a styled HTML email and sends via Gmail SMTP

## Setup

### Prerequisites

- Python 3.9+
- A [Gmail app password](https://support.google.com/accounts/answer/185833)
- A [DeepSeek API key](https://platform.deepseek.com/)

### Install

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

### Environment variables

Create a `.env` file in the project root (used locally; GitHub Actions uses repository secrets):

```
DEEPSEEK_API_KEY=sk-...
GMAIL_USER=you@gmail.com
GMAIL_APP_PASSWORD=abcd efgh ijkl mnop
TO_EMAIL=recipient1@example.com,recipient2@example.com
```

| Variable             | Required | Description                               |
| -------------------- | -------- | ----------------------------------------- |
| `DEEPSEEK_API_KEY`   | Yes      | DeepSeek API key                          |
| `DEEPSEEK_MODEL`     | No       | Model name (default: `deepseek-chat`)     |
| `GMAIL_USER`         | Yes      | Gmail address used to send the email      |
| `GMAIL_APP_PASSWORD` | Yes      | Gmail app password                        |
| `TO_EMAIL`           | Yes      | Comma-separated recipient email addresses |

### Customize recommendations

Edit `prompt.md` to change food preferences, decision rules, and output style. The default prompt is tuned for a student who prefers Chinese/Asian comfort foods.

## Usage

### Run locally

```bash
python recommend_daily.py
```

### Automated (GitHub Actions)

The included workflow (`.github/workflows/eatery_recommend.yml`) runs daily at 10:00 AM UTC. You can also trigger it manually from the GitHub Actions UI or with:

```bash
gh workflow run "Eatery West Campus Recommendation"
```

Store the environment variables as repository secrets in GitHub.

## Configuration

- **`prompt.md`** — LLM system prompt controlling food preferences and recommendation style
- **Meal time windows** — defined in `recommend_daily.py` (`MEAL_WINDOWS`); defaults are 6-11 AM, 11 AM-4 PM, 4-9 PM Eastern
- **Eatery denylist** — `EATERY_DENYLIST` in `recommend_daily.py` to exclude specific eateries
