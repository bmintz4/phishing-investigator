import base64
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.intel.cache import CallRateLimiter, ReputationCache
from src.intel.url_reputation import analyze_url_reputation, get_url_analysis_stats


STATS = {
    "harmless": 72,
    "malicious": 2,
    "suspicious": 1,
    "undetected": 10,
    "timeout": 0,
}


class FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {
            "data": {
                "attributes": {
                    "categories": {"vendor": "phishing"},
                    "last_analysis_date": 1_700_000_000,
                    "last_analysis_results": {
                        "scanner": {
                            "category": "malicious",
                            "engine_name": "scanner",
                            "method": "blacklist",
                            "result": "phishing",
                        }
                    },
                    "last_analysis_stats": STATS,
                    "reputation": -10,
                    "tags": ["phishing"],
                    "url": "https://example.com/a?b=1",
                },
                "id": "url-sha256",
                "links": {"self": "https://www.virustotal.com/api/v3/urls/id"},
                "type": "url",
            }
        }


class FakeHttpClient:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


def analyze(html, client):
    results, _ = analyze_url_reputation(
        html,
        "test-key",
        http_client=client,
        cache=ReputationCache(),
        rate_limiter=CallRateLimiter(),
    )
    return results


def test_url_info_uses_unpadded_base64_id_and_api_key_header():
    client = FakeHttpClient()
    url = "https://example.com/a?b=1"

    result = get_url_analysis_stats(url, "secret", http_client=client)

    expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert client.calls == [
        (
            f"https://www.virustotal.com/api/v3/urls/{expected_id}",
            {"headers": {"x-apikey": "secret"}, "timeout": 10},
        )
    ]
    assert result == STATS
    assert set(result) == {
        "harmless",
        "malicious",
        "suspicious",
        "timeout",
        "undetected",
    }


def test_duplicate_urls_are_ignored_and_two_unique_urls_are_both_analyzed():
    client = FakeHttpClient()
    html = """
    <a href="https://example.com/a">one</a>
    <a href="https://example.com/a">duplicate</a>
    <a href="https://example.com/b">two</a>
    """

    results = analyze(html, client)

    assert len(client.calls) == 2
    assert [result["URL"] for result in results] == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert [result["status"] for result in results] == ["Analyzed", "Analyzed"]


def test_more_than_two_urls_are_analyzed_once_per_domain_and_cloned():
    client = FakeHttpClient()
    html = """
    <a href="https://example.com/a">one</a>
    <a href="https://example.com/b">two</a>
    <a href="https://other.example/c">three</a>
    """

    results = analyze(html, client)

    assert len(client.calls) == 2
    assert [result["status"] for result in results] == [
        "Analyzed",
        "Clone",
        "Analyzed",
    ]
    assert results[1]["last analysis stats"] == results[0]["last analysis stats"]


def test_only_first_four_domains_are_called_and_the_rest_are_untested():
    client = FakeHttpClient()
    html = "".join(
        f'<a href="https://domain{index}.example/path">link</a>'
        for index in range(1, 7)
    )

    results = analyze(html, client)

    assert len(client.calls) == 4
    assert [result["status"] for result in results] == [
        "Analyzed",
        "Analyzed",
        "Analyzed",
        "Analyzed",
        "Untested",
        "Untested",
    ]
    assert results[-1]["last analysis stats"] is None


def test_non_web_links_are_not_sent_to_virustotal():
    client = FakeHttpClient()
    html = """
    <a href="mailto:help@example.com">email</a>
    <a href="javascript:alert(1)">script</a>
    """

    assert analyze(html, client) == []
    assert client.calls == []


def test_no_web_links_reports_that_nothing_was_analyzed():
    results, any_analyzed = analyze_url_reputation(
        '<a href="mailto:help@example.com">email</a>',
        "test-key",
        http_client=FakeHttpClient(),
        cache=ReputationCache(),
        rate_limiter=CallRateLimiter(),
    )

    assert results == []
    assert any_analyzed is False


def test_quota_skipped_url_reports_that_nothing_was_analyzed():
    results, any_analyzed = analyze_url_reputation(
        '<a href="https://example.com/login">login</a>',
        "test-key",
        http_client=FakeHttpClient(),
        cache=ReputationCache(),
        rate_limiter=CallRateLimiter(max_calls=0),
    )

    assert results[0]["status"] == "Untested"
    assert results[0]["last analysis stats"] is None
    assert any_analyzed is False


def test_visible_url_in_html_is_analyzed_without_an_anchor():
    client = FakeHttpClient()

    results = analyze("<p>Visit https://example.com/login</p>", client)

    assert len(client.calls) == 1
    assert results[0]["URL"] == "https://example.com/login"
    assert results[0]["status"] == "Analyzed"


def test_repeated_url_uses_cached_stats_without_another_api_call():
    client = FakeHttpClient()
    cache = ReputationCache()
    limiter = CallRateLimiter()
    html = '<a href="https://example.com/login">login</a>'

    first, first_analyzed = analyze_url_reputation(
        html,
        "test-key",
        http_client=client,
        cache=cache,
        rate_limiter=limiter,
    )
    second, second_analyzed = analyze_url_reputation(
        html,
        "test-key",
        http_client=client,
        cache=cache,
        rate_limiter=limiter,
    )

    assert len(client.calls) == 1
    assert second == first
    assert first_analyzed is True
    assert second_analyzed is True
