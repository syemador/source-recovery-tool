"""
GitHub Searcher
===============
Constructs multi-term search queries from ranked internal features and
retrieves candidate source files from the GitHub Code Search API.

Design Decisions (post-review):
  - Function names are NEVER included in queries. The tool assumes
    stripped binaries where names are unavailable.
  - No language filters (language:c, etc.). Multi-term queries are
    specific enough without them, and removing filters allows
    cross-language matches.
  - Queries combine features from different categories (constant + string,
    constant + constant, string + API call) for maximum precision.

Rate Limiting:
  GitHub's search API is rate-limited (10 requests/min unauthenticated,
  30/min authenticated). The searcher enforces minimum intervals between
  requests and retries on 403 responses.
"""

import base64
import time
import requests
from dataclasses import dataclass, field
from modules.feature_ranker import RankedFeatures


GITHUB_SEARCH_URL = "https://api.github.com/search/code"


@dataclass
class SearchCandidate:
    """A candidate source file from GitHub."""
    file_url: str = ""           # GitHub API URL
    html_url: str = ""           # Human-readable URL
    repo_full_name: str = ""     # e.g., "madler/zlib"
    file_path: str = ""          # e.g., "inflate.c"
    file_name: str = ""
    score: float = 0.0           # GitHub relevance score
    query_hits: int = 0          # How many of our queries matched this file
    matched_queries: list = field(default_factory=list)
    raw_content: str = ""        # Fetched source content (filled later)

    def to_dict(self) -> dict:
        return {
            "html_url": self.html_url,
            "repo": self.repo_full_name,
            "file_path": self.file_path,
            "score": self.score,
            "query_hits": self.query_hits,
            "matched_queries": self.matched_queries,
        }


class GitHubSearcher:
    """Searches GitHub for candidate source files matching extracted features."""

    def __init__(self, token: str = ""):
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"

        self._request_count = 0
        self._last_request_time = 0.0

    def search(self, features: RankedFeatures, top_k: int = 50) -> list[SearchCandidate]:
        """
        Build queries from ranked features and search GitHub.

        Returns up to top_k de-duplicated candidates sorted by relevance.
        """
        queries = self._build_queries(features)

        if not queries:
            print("    [GitHub] No viable search queries could be constructed.")
            return []

        print(f"    [GitHub] Constructed {len(queries)} search queries.")

        # Execute queries and collect candidates
        candidates_by_url: dict[str, SearchCandidate] = {}
        per_query_limit = max(10, top_k // len(queries))

        for i, query in enumerate(queries):
            print(f"    [GitHub] Query {i+1}/{len(queries)}: {query[:80]}...")
            self._rate_limit()

            results = self._execute_query(query, per_page=per_query_limit)

            for item in results:
                url = item.get("html_url", "")
                if url in candidates_by_url:
                    candidates_by_url[url].query_hits += 1
                    candidates_by_url[url].matched_queries.append(query[:60])
                    # Boost score for multi-query matches
                    candidates_by_url[url].score += item.get("score", 0)
                else:
                    candidates_by_url[url] = SearchCandidate(
                        file_url=item.get("url", ""),
                        html_url=url,
                        repo_full_name=item.get("repository", {}).get("full_name", ""),
                        file_path=item.get("path", ""),
                        file_name=item.get("name", ""),
                        score=item.get("score", 0),
                        query_hits=1,
                        matched_queries=[query[:60]],
                    )

            if len(candidates_by_url) >= top_k:
                break

        # Sort: multi-query hits first, then by score
        all_candidates = list(candidates_by_url.values())
        all_candidates.sort(key=lambda c: (c.query_hits, c.score), reverse=True)

        # Fetch source content for top candidates (for LLM verification)
        top_candidates = all_candidates[:top_k]
        self._fetch_file_contents(top_candidates)

        return top_candidates

    def _build_queries(self, features: RankedFeatures) -> list[str]:
        """
        Construct GitHub Code Search queries from ranked features.

        Design Decision (post-review):
          - Function names are EXCLUDED from queries. In real-world reverse
            engineering, binaries are stripped — names like 'adler32' are
            unavailable. The tool must work without them.
          - Language filters (language:c) are REMOVED. Multi-term internal
            feature queries are specific enough on their own, and removing
            the filter allows cross-language matches (e.g., C reimplementations
            in Rust or Go that share the same constants).
          - Queries are built entirely from internal logic signatures:
            rare constants, unique strings, and distinctive API calls.

        Strategy: combine multiple features per query for precision.
        A single term like '0xfff1' is too broad; pairing it with a
        string like '"incorrect data check"' narrows to the exact library.
        """
        queries = []

        strings = [s["value"] for s in features.unique_strings[:5]]
        constants = [c["hex"] for c in features.rare_constants[:5]]
        ext_calls = [c for c in features.external_calls[:5] if len(c) > 3]

        # ── Strategy 1: Constant + String pairs (highest precision) ───
        # Combining two independent feature types is the strongest signal
        for c in constants[:3]:
            for s in strings[:2]:
                truncated = s[:50] if len(s) > 50 else s
                queries.append(f'{c} "{truncated}"')

        # ── Strategy 2: Multi-constant queries ────────────────────────
        # Two rare constants together are very specific
        if len(constants) >= 2:
            queries.append(f'{constants[0]} {constants[1]}')
        if len(constants) >= 3:
            queries.append(f'{constants[0]} {constants[2]}')

        # ── Strategy 3: String + API call pairs ───────────────────────
        for s in strings[:2]:
            for call in ext_calls[:2]:
                truncated = s[:50] if len(s) > 50 else s
                queries.append(f'"{truncated}" "{call}"')

        # ── Strategy 4: Constant + API call pairs ─────────────────────
        for c in constants[:2]:
            for call in ext_calls[:2]:
                queries.append(f'{c} "{call}"')

        # ── Strategy 5: Individual strings (fallback, broadest) ───────
        for s in strings[:3]:
            truncated = s[:60] if len(s) > 60 else s
            queries.append(f'"{truncated}"')

        # ── Strategy 6: String pairs ─────────────────────────────────
        if len(strings) >= 2:
            queries.append(f'"{strings[0][:40]}" "{strings[1][:40]}"')

        # ── Strategy 7: Individual rare constants (broadest fallback) ─
        for c in constants[:3]:
            queries.append(f'{c}')

        # ── Strategy 8: API calls alone (last resort for wrapper functions) ─
        # Handles functions with no constants or strings but distinctive
        # API calls (e.g., OpenSSL EVP_*, BIO_*, SSL_* functions)
        if not strings and not constants:
            for call in ext_calls[:3]:
                queries.append(f'"{call}"')
            if len(ext_calls) >= 2:
                queries.append(f'"{ext_calls[0]}" "{ext_calls[1]}"')

        # De-duplicate queries
        seen = set()
        unique_queries = []
        for q in queries:
            if q not in seen:
                seen.add(q)
                unique_queries.append(q)

        return unique_queries[:15]  # Cap at 15 queries to respect rate limits

    def _execute_query(self, query: str, per_page: int = 10, max_retries: int = 2) -> list[dict]:
        """Execute a single GitHub code search query with retry on rate limit."""
        params = {
            "q": query,
            "per_page": min(per_page, 100),
        }

        for attempt in range(max_retries + 1):
            try:
                resp = requests.get(
                    GITHUB_SEARCH_URL,
                    headers=self.headers,
                    params=params,
                    timeout=30,
                )
                self._request_count += 1

                if resp.status_code == 403:
                    reset_time = resp.headers.get("X-RateLimit-Reset")
                    if reset_time and attempt < max_retries:
                        wait = max(0, int(reset_time) - int(time.time())) + 1
                        print(f"    [GitHub] Rate limited. Waiting {min(wait, 60)}s then retrying...")
                        time.sleep(min(wait, 60))
                        continue  # Retry the same query
                    print(f"    [GitHub] Rate limited. Max retries exceeded.")
                    return []

                if resp.status_code == 422:
                    print(f"    [GitHub] Query rejected (422). Skipping.")
                    return []

                if resp.status_code != 200:
                    print(f"    [GitHub] HTTP {resp.status_code}: {resp.text[:200]}")
                    return []

                data = resp.json()
                return data.get("items", [])

            except requests.RequestException as e:
                print(f"    [GitHub] Request failed: {e}")
                return []

        return []

    def _rate_limit(self):
        """Enforce minimum delay between requests."""
        min_interval = 6.0 if not self.token else 2.5  # Respect GitHub limits
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    def _fetch_file_contents(self, candidates: list[SearchCandidate], max_fetch: int = 15):
        """
        Fetch the raw source content for the top candidates.

        Only fetches the top `max_fetch` to stay within rate limits.
        The LLM verifier will use these for detailed comparison.
        """
        for i, candidate in enumerate(candidates[:max_fetch]):
            if not candidate.file_url:
                continue

            self._rate_limit()
            try:
                # Use the GitHub API URL to get file content
                resp = requests.get(
                    candidate.file_url,
                    headers=self.headers,
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content_b64 = data.get("content", "")
                    if content_b64:
                        candidate.raw_content = base64.b64decode(content_b64).decode(
                            "utf-8", errors="replace"
                        )
                        # Truncate very large files (keep first 15k chars)
                        if len(candidate.raw_content) > 15000:
                            candidate.raw_content = candidate.raw_content[:15000] + "\n... [truncated]"
                else:
                    print(f"    [GitHub] Could not fetch {candidate.file_name}: HTTP {resp.status_code}")

            except Exception as e:
                print(f"    [GitHub] Error fetching {candidate.file_name}: {e}")

        fetched = sum(1 for c in candidates[:max_fetch] if c.raw_content)
        print(f"    [GitHub] Fetched content for {fetched}/{min(max_fetch, len(candidates))} candidates.")
