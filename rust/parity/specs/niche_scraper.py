"""Parity spec for PiNicheScraper.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

PARITY CAVEAT (read before adding to the gating suite): the original
`PiNicheScraper.scrape_niche` sets `scraped_at = datetime.datetime.now()
.isoformat()`. That field is wall-clock and therefore NON-DETERMINISTIC — it
differs on every invocation, so an exact `==` comparison against the Rust port
can never pass on `scraped_at`. The harness's NORMALIZE mechanism only sorts
list fields; it cannot neutralise a timestamp. Every other field IS
deterministic: the ingested tweets/repos are hardcoded and the three
prompt-injection regexes never match those fixed strings, so
`anomalies_detected` is always `[]`, `success` is always `True`, and the
`tweets`/`github_repos` lists are always the same two-element mocks regardless
of input (niche / max_items / github_stars_threshold / target_handles) or of
PI_SCRAPER_STRICT_MODE. The samples below exercise input-field and env-branch
diversity to prove the rest of the output is stable.
"""
from _util import load_py_agent

RUST_NAME = "PiNicheScraper"

_mod = load_py_agent("pi_niche_scraper.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiNicheScraper()
    out = agent.scrape_niche(_mod.ScraperInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean/default niche
    {"input": {"niche": "AI"}},
    # explicit non-default scalar inputs (do not affect the mock feed)
    {"input": {"niche": "Web3", "max_items": 10, "github_stars_threshold": 1000}},
    # curated target handles supplied
    {"input": {"niche": "Robotics", "target_handles": ["@karpathy", "@levelsio"]}},
    # all fields populated
    {"input": {"niche": "Quant", "max_items": 1, "github_stars_threshold": 50,
               "target_handles": ["@a"]}},
    # edge: empty niche string (still satisfies required str field)
    {"input": {"niche": ""}},
    # edge: empty handle list explicitly
    {"input": {"niche": "DeFi", "target_handles": []}},
    # strict-mode env ON (no anomalies in mock feed -> feed preserved, success)
    {"input": {"niche": "AI"},
     "env": {"PI_SCRAPER_STRICT_MODE": "true"}},
    # strict-mode env OFF (same: feed preserved, success True)
    {"input": {"niche": "AI"},
     "env": {"PI_SCRAPER_STRICT_MODE": "false"}},
]

# `scraped_at` is datetime.now().isoformat() in the original — non-deterministic
# wall-clock, impossible to byte-match across instants. Excluded from parity;
# all other fields (tweets, repos, anomalies) are deterministic and compared.
def sanitize(out: dict) -> dict:
    out = dict(out)
    out.pop("scraped_at", None)
    return out
