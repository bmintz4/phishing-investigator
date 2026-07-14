## Retrieve VirusTotal's latest reputation statistics for URLs in HTML.

from __future__ import annotations

import base64
import os
from collections import OrderedDict
from typing import Any
from urllib.parse import urlsplit

import requests

from src.ingestion.html_email import URL_REGEX, extract_links, html_to_text
from src.intel.cache import (
    DEFAULT_REPUTATION_CACHE,
    VIRUSTOTAL_RATE_LIMITER,
    CallRateLimiter,
    ReputationCache,
)

VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"
STAT_NAMES = ("harmless", "malicious", "suspicious", "undetected", "timeout")


def analyze_url_reputation(
    raw_html: str,
    api_key: str | None = None,
    *,
    http_client: Any = requests,
    cache: ReputationCache = DEFAULT_REPUTATION_CACHE,
    rate_limiter: CallRateLimiter = VIRUSTOTAL_RATE_LIMITER,
) -> tuple[list[dict[str, Any]], bool]:
    """Analyze unique HTTP(S) links and report whether any produced stats.

    With at most two URLs, each URL is looked up. With more than two, the first
    URL from each of the first four hostnames is looked up and its statistics
    are copied to the remaining URLs on that hostname. The returned boolean is
    false when no URL has usable analysis statistics.
    """
    urls = _extract_unique_web_urls(raw_html)
    if not urls:
        return [], False

    key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        raise ValueError(
            "VirusTotal API key is missing. Set VIRUSTOTAL_API_KEY in "
            ".streamlit/secrets.toml or in the environment."
        )

    if len(urls) <= 2:
        results = [
            _analyze_one(url, key, http_client, cache, rate_limiter)
            for url in urls
        ]
        return results, _has_analyzed_url(results)

    urls_by_domain: OrderedDict[str, list[str]] = OrderedDict()
    for url in urls:
        urls_by_domain.setdefault(_domain_for_url(url), []).append(url)

    results_by_url: dict[str, dict[str, Any]] = {}
    for domain_urls in list(urls_by_domain.values())[:4]:
        representative = domain_urls[0]
        analyzed = _analyze_one(
            representative, key, http_client, cache, rate_limiter
        )
        results_by_url[representative] = analyzed

        if analyzed["status"] == "Untested":
            for url in domain_urls[1:]:
                results_by_url[url] = _result(url, "Untested", None)
            continue

        for url in domain_urls[1:]:
            results_by_url[url] = _result(
                url, "Clone", analyzed["last analysis stats"]
            )

    for domain_urls in list(urls_by_domain.values())[4:]:
        for url in domain_urls:
            results_by_url[url] = _result(url, "Untested", None)

    results = [results_by_url[url] for url in urls]
    return results, _has_analyzed_url(results)


def get_url_analysis_stats(
    url: str,
    api_key: str,
    *,
    http_client: Any = requests,
    timeout: float = 10,
) -> dict[str, int]:
    """Fetch and normalize ``last_analysis_stats`` for one URL."""
    url_id = (
        base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    )
    response = http_client.get(
        VIRUSTOTAL_URL_ENDPOINT.format(url_id=url_id),
        headers={"x-apikey": api_key},
        timeout=timeout,
    )
    response.raise_for_status()

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "VirusTotal response did not contain last_analysis_stats"
        ) from exc

    return {name: int(stats.get(name, 0)) for name in STAT_NAMES}


def _analyze_one(
    url: str,
    api_key: str,
    http_client: Any,
    cache: ReputationCache,
    rate_limiter: CallRateLimiter,
) -> dict[str, Any]:
    cached = cache.get(url)
    if cached is not None:
        return _result(url, "Analyzed", cached)

    if not rate_limiter.try_acquire():
        return _result(url, "Untested", None)

    try:
        stats = get_url_analysis_stats(url, api_key, http_client=http_client)
    except (requests.RequestException, ValueError) as exc:
        result = _result(url, "Analyzed", None)
        result["Error"] = str(exc)
        return result

    cache.set(url, stats)
    return _result(url, "Analyzed", stats)


def _extract_unique_web_urls(raw_html: str) -> list[str]:
    unique_urls: dict[str, None] = {}
    candidates = [link["address"] for link in extract_links(raw_html)]
    candidates.extend(URL_REGEX.findall(html_to_text(raw_html)))

    for candidate in candidates:
        url = candidate.strip()
        try:
            parsed = urlsplit(url)
            is_web_url = parsed.scheme.casefold() in {"http", "https"} and bool(
                parsed.hostname
            )
        except ValueError:
            is_web_url = False

        if is_web_url:
            unique_urls.setdefault(url, None)
    return list(unique_urls)


def _domain_for_url(url: str) -> str:
    return (urlsplit(url).hostname or "").casefold()


def _has_analyzed_url(results: list[dict[str, Any]]) -> bool:
    return any(result["last analysis stats"] is not None for result in results)


def _result(
    url: str, status: str, stats: dict[str, int] | None
) -> dict[str, Any]:
    return {
        "URL": url,
        "status": status,
        "last analysis stats": stats.copy() if stats is not None else None,
    }
