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

    dns_records = DNSService.get_records(domain)
    whois_task = asyncio.to_thread(WhoisService.get_metadata, domain)
    web_task = WebService.analyze_website(domain)

    metadata, web_analysis = await asyncio.gather(whois_task, web_task)

    email_auth = DNSService.analyze_email_auth(domain, dns_records["txt"])
    cdn = DNSService.detect_cdn(dns_records)
    
    # New Gmail-centric checks
    dns_records["cdn"] = cdn
    dns_records["mx_provider"] = DNSService.detect_mx_provider(dns_records["mx"])
    dns_records["reverse_dns"] = DNSService.get_reverse_dns(dns_records["a"][0]) if dns_records["a"] else None
    
    email_auth["google_verification"] = any("google-site-verification" in txt.lower() for txt in dns_records["txt"])

    report_data = {
        "domain": domain,
        "dns": dns_records,
        "email_auth": email_auth,
        "metadata": metadata,
        "web": web_analysis,
        "reputation": {"blacklisted": False, "blacklist_count": 0, "mx_quality": "Good" if dns_records["mx"] else "None"}
    }

    report_data["score"] = AnalysisEngine.calculate_score(report_data)
    return DomainReport(**report_data)

@app.post("/analyze", response_model=ComparisonReport)
async def analyze_domains(request: AnalysisRequest):
    if len(request.best) > 100 or len(request.bad) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 domains per side allowed.")

    best_tasks = [analyze_single_domain(d) for d in request.best if d.strip()]
    bad_tasks = [analyze_single_domain(d) for d in request.bad if d.strip()]

    best_results = await asyncio.gather(*best_tasks, return_exceptions=True)
    bad_results = await asyncio.gather(*bad_tasks, return_exceptions=True)

    valid_best = [r for r in best_results if isinstance(r, DomainReport)]
    valid_bad = [r for r in bad_results if isinstance(r, DomainReport)]

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
