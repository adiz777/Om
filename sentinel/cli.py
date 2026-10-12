"""CLI client for a running Om Sentinel API."""
import argparse, json, os, sys
import httpx

def main():
    parser = argparse.ArgumentParser(description="Om Sentinel passive enrichment CLI")
    parser.add_argument("domain", help="Domain you own or are authorised to assess")
    parser.add_argument("--cve-keyword", help="Technology/product keyword for public NVD search")
    parser.add_argument("--no-ai", action="store_true", help="Skip optional AI analysis")
    parser.add_argument("--url", default="http://127.0.0.1:8787", help="Om Sentinel API base URL")
    args = parser.parse_args()
    key = os.getenv("OM_SENTINEL_API_KEY", "")
    if not key:
        parser.error("Set OM_SENTINEL_API_KEY in the environment")
    try:
        response = httpx.post(args.url.rstrip("/") + "/api/enrich", headers={"X-Om-Api-Key": key}, json={"domain": args.domain, "cve_keyword": args.cve_keyword, "use_ai": not args.no_ai}, timeout=40)
        response.raise_for_status()
        print(json.dumps(response.json(), indent=2))
    except httpx.HTTPError as exc:
        print(f"Om Sentinel request failed: {exc}", file=sys.stderr); return 1
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
