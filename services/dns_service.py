import dns.asyncresolver
import dns.reversename
import re
import asyncio

class DNSService:
    @staticmethod
    async def get_records(domain: str):
        records = {"a": [], "mx": [], "ns": [], "txt": [], "ttl": {}}
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        async def resolve_type(rtype):
            try:
                answers = await resolver.resolve(domain, rtype)
                records["ttl"][rtype] = answers.ttl
                for rdata in answers:
                    if rtype == "A": records["a"].append(str(rdata))
                    elif rtype == "MX": records["mx"].append(str(rdata.exchange).rstrip('.'))
                    elif rtype == "NS": records["ns"].append(str(rdata.target).rstrip('.'))
                    elif rtype == "TXT": records["txt"].append(str(rdata).strip('"'))
            except Exception:
                pass

        await asyncio.gather(*(resolve_type(t) for t in ["A", "MX", "NS", "TXT"]))
        return records

    @staticmethod
    async def analyze_email_auth(domain: str, txt_records: list):
        auth = {
            "spf": {"exists": False, "valid": False, "raw": "", "size": 0, "includes_count": 0, "includes": []},
            "dkim": {"exists": False, "selectors": []},
            "dmarc": {"exists": False, "policy": "none", "raw": ""},
            "bimi": {"exists": False, "raw": ""},
            "google_verification": False
        }
        
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5

        # SPF
        for record in txt_records:
            if record.startswith("v=spf1"):
                auth["spf"]["exists"] = True
                auth["spf"]["raw"] = record
                auth["spf"]["size"] = len(record)
                includes = re.findall(r"include:([^\s]+)", record)
                auth["spf"]["includes_count"] = len(includes)
                auth["spf"]["includes"] = includes
                auth["spf"]["valid"] = any(record.endswith(term) for term in ["-all", "~all", "?all"])
                break
        
        auth["google_verification"] = any("google-site-verification" in txt.lower() for txt in txt_records)

        # Concurrent DMARC, BIMI, and DKIM checks
        async def check_dmarc():
            try:
                answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if record.startswith("v=DMARC1"):
                        auth["dmarc"]["exists"] = True
                        auth["dmarc"]["raw"] = record
                        policy_match = re.search(r"p=([^;]+)", record)
                        auth["dmarc"]["policy"] = policy_match.group(1) if policy_match else "none"
                        break
            except Exception: pass

        async def check_bimi():
            try:
                answers = await resolver.resolve(f"default._bimi.{domain}", "TXT")
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if record.startswith("v=BIMI1"):
                        auth["bimi"]["exists"] = True
                        auth["bimi"]["raw"] = record
                        break
            except Exception: pass

        async def check_dkim_selector(selector):
            try:
                await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                auth["dkim"]["exists"] = True
                auth["dkim"]["selectors"].append(selector)
            except Exception: pass

        dkim_tasks = [check_dkim_selector(s) for s in ["default", "google", "mandrill", "mail", "k1", "dkim"]]
        await asyncio.gather(check_dmarc(), check_bimi(), *dkim_tasks)

        return auth

    @staticmethod
    def detect_mx_provider(mx_records: list):
        if not mx_records: return "None"
        providers = {
            "google": ["google.com", "googlemail.com"],
            "outlook": ["outlook.com", "protection.outlook.com"],
            "mimecast": ["mimecast.com"],
            "proofpoint": ["pphosted.com"],
            "zoho": ["zoho.com"]
        }
        for mx in mx_records:
            for provider, domains in providers.items():
                if any(d in mx.lower() for d in domains):
                    return provider.capitalize()
        return "Custom/Unknown"

    @staticmethod
    async def get_reverse_dns(ip: str):
        if not ip: return None
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 1.5
            resolver.lifetime = 1.5
            addr = dns.reversename.from_address(ip)
            answers = await resolver.resolve(addr, "PTR")
            return str(answers[0]).rstrip('.')
        except Exception: return None

    @staticmethod
    def detect_cdn(records: dict):
        cdn_keywords = {"cloudflare": "cloudflare", "cloudfront": "cloudfront", "akamai": "akamai", "fastly": "fastly", "google": "google", "azure": "azure"}
        for ns in records.get("ns", []):
            for cdn, keyword in cdn_keywords.items():
                if keyword in ns.lower(): return cdn.capitalize()
        return None
