import os
import re
from typing import List

from . import extractor


def login_and_scrape(login_url: str, dashboard_url: str, out_path: str = "jwt.txt") -> List[str]:
    """Interactively login and scrape JWTs from network traffic and storage.

    The function launches Chromium, navigates to ``login_url`` and pauses so the
    user can complete authentication. After pressing Enter, the browser visits
    ``dashboard_url`` and collects any JWTs observed in network responses,
    request/response headers, cookies, and web storage. All discovered tokens are
    written line-by-line to ``out_path`` and returned as a list.
    """
    tokens: set[str] = set()

    headless = os.getenv("JWTEK_HEADLESS", "").lower() in {"1", "true"}

    from playwright.sync_api import sync_playwright  # type: ignore

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()

        def handle_response(response):
            try:
                body = response.text()
            except Exception:
                body = ""
            tokens.update(re.findall(extractor.JWT_REGEX, body))
            for value in response.headers.values():
                tokens.update(re.findall(extractor.JWT_REGEX, value))

        def handle_request(request):
            for value in request.headers.values():
                tokens.update(re.findall(extractor.JWT_REGEX, value))

        page.on("response", handle_response)
        page.on("request", handle_request)

        page.goto(login_url)
        input("Press Enter to continue...")
        page.goto(dashboard_url)

        # Extract from cookies
        for cookie in context.cookies():
            tokens.update(re.findall(extractor.JWT_REGEX, cookie.get("value", "")))

        # Extract from localStorage and sessionStorage
        for storage in ("localStorage", "sessionStorage"):
            try:
                data = page.evaluate(f"() => Object.values({storage}).join(' ')")
            except Exception:
                data = ""
            tokens.update(re.findall(extractor.JWT_REGEX, data))

        browser.close()

    with open(out_path, "w") as f:
        for t in tokens:
            f.write(t + "\n")

    return list(tokens)
