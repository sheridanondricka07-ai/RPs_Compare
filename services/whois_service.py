import whois
from datetime import datetime

class WhoisService:
    @staticmethod
    def get_metadata(domain: str):
        metadata = {
            "age_days": None,
            "created_date": None,
            "registrar": None,
            "tld": domain.split(".")[-1]
        }
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                metadata["created_date"] = creation_date.isoformat()
                delta = datetime.now() - creation_date
                metadata["age_days"] = delta.days
            
            metadata["registrar"] = w.registrar
        except Exception:
            pass
        return metadata
