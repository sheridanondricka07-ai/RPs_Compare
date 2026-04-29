import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
from models import AnalysisRequest, DomainReport, ComparisonReport
from services.dns_service import DNSService
from services.whois_service import WhoisService
from services.web_service import WebService
from services.analysis_engine import AnalysisEngine

app = FastAPI(title="Domain Comparator Pro API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

async def analyze_single_domain(domain: str) -> DomainReport:
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Empty domain")

    dns_records = await DNSService.get_records(domain)
    whois_task = asyncio.to_thread(WhoisService.get_metadata, domain)
    web_task = WebService.analyze_website(domain)

    metadata, web_analysis = await asyncio.gather(whois_task, web_task)

    # Structural Analysis
    domain_parts = domain.split('.')
    main_name = domain_parts[0]
    
    metadata["length"] = len(main_name)
    metadata["has_digits"] = any(char.isdigit() for char in main_name)
    metadata["hyphen_count"] = main_name.count('-')
    
    common_keywords = ["bank", "login", "update", "verify", "secure", "mail", "office", "support", "admin", "cloud"]
    metadata["keywords"] = [k for k in common_keywords if k in main_name]

    email_auth = await DNSService.analyze_email_auth(domain, dns_records["txt"])
    cdn = DNSService.detect_cdn(dns_records)
    
    # New Gmail-centric checks
    dns_records["cdn"] = cdn
    dns_records["mx_provider"] = DNSService.detect_mx_provider(dns_records["mx"])
    dns_records["reverse_dns"] = await DNSService.get_reverse_dns(dns_records["a"][0]) if dns_records["a"] else None
    
    # Ensure metadata has all required fields for Pydantic validation
    metadata["length"] = metadata.get("length", 0)
    metadata["has_digits"] = metadata.get("has_digits", False)
    metadata["hyphen_count"] = metadata.get("hyphen_count", 0)
    metadata["keywords"] = metadata.get("keywords", [])
    metadata["tld"] = metadata.get("tld") or domain.split('.')[-1]

    report_data = {
        "domain": domain,
        "dns": dns_records,
        "email_auth": email_auth,
        "metadata": metadata,
        "web": web_analysis,
        "reputation": {"blacklisted": False, "blacklist_count": 0, "mx_quality": "Good" if dns_records["mx"] else "None"}
    }

    try:
        report_data["score"] = AnalysisEngine.calculate_score(report_data)
        return DomainReport(**report_data)
    except Exception as e:
        print(f"Validation error for {domain}: {e}")
        return None

@app.post("/analyze", response_model=ComparisonReport)
async def analyze_domains(request: AnalysisRequest):
    if len(request.best) > 100 or len(request.bad) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 domains per side allowed.")

    # Limit concurrency to avoid overwhelming the server or hitting rate limits
    semaphore = asyncio.Semaphore(10)

    async def sem_analyze(domain):
        async with semaphore:
            try:
                # Set a strict per-domain timeout
                return await asyncio.wait_for(analyze_single_domain(domain), timeout=15.0)
            except Exception:
                return None

    best_tasks = [sem_analyze(d) for d in request.best if d.strip()]
    bad_tasks = [sem_analyze(d) for d in request.bad if d.strip()]

    try:
        # Global timeout to ensure we return something before Render kills the request (30s)
        results = await asyncio.wait_for(
            asyncio.gather(*best_tasks, *bad_tasks), 
            timeout=25.0
        )
        
        best_results = results[:len(best_tasks)]
        bad_results = results[len(best_tasks):]
    except asyncio.TimeoutError:
        # On timeout, we can't easily get partial results from gather
        # So we use a different approach if we want partials, but for now let's just fail gracefully
        # or try to return whatever is already done by using return_exceptions=True
        raise HTTPException(status_code=504, detail="Analysis timed out. Try fewer domains at once.")

    valid_best = [r for r in best_results if isinstance(r, DomainReport)]
    valid_bad = [r for r in bad_results if isinstance(r, DomainReport)]

    if not valid_best and not valid_bad:
        raise HTTPException(status_code=400, detail="No domains could be analyzed. Check your input.")

    comparison = AnalysisEngine.compare_groups(
        [r.model_dump() for r in valid_best],
        [r.model_dump() for r in valid_bad]
    )

    return ComparisonReport(
        best_domains=valid_best,
        bad_domains=valid_bad,
        **comparison
    )

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
