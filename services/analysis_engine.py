import pandas as pd
from typing import List, Dict, Any
from .dns_service import DNSService

class AnalysisEngine:
    @staticmethod
    def calculate_score(report_data: dict):
        score = 0
        
        # Email Auth (Max 50)
        if report_data["email_auth"]["spf"]["valid"]: score += 15
        if report_data["email_auth"]["dmarc"]["exists"]:
            policy = report_data["email_auth"]["dmarc"]["policy"]
            if policy in ["reject", "quarantine"]: score += 20
            else: score += 10
        if report_data["email_auth"]["dkim"]["exists"]: score += 5
        if report_data["email_auth"]["bimi"]["exists"]: score += 5
        if report_data["email_auth"].get("google_verification"): score += 5
            
        # Metadata (Max 20)
        age = report_data["metadata"]["age_days"]
        if age:
            if age > 365 * 2: score += 20
            elif age > 365: score += 10
            
        # Infrastructure (Max 20)
        if report_data["dns"]["mx"]: score += 5
        if report_data["dns"]["a"]: score += 5
        if report_data["dns"].get("reverse_dns"): score += 10
        
        # Web (Max 10)
        if report_data["web"]["https"]: score += 5
        if report_data["web"]["status_code"] == 200: score += 5
            
        return min(score, 100)

    @staticmethod
    def compare_groups(best: List[Dict], bad: List[Dict]):
        def get_stats(group):
            df = pd.json_normalize(group)
            if df.empty: return {}
            
            stats = {
                "avg_score": df["score"].mean() if "score" in df else 0,
                "spf_valid_pct": (df["email_auth.spf.valid"].sum() / len(df) * 100) if "email_auth.spf.valid" in df else 0,
                "dmarc_strict_pct": (df[df["email_auth.dmarc.policy"].isin(["reject", "quarantine"])].shape[0] / len(df) * 100) if "email_auth.dmarc.policy" in df else 0,
                "https_pct": (df["web.https"].sum() / len(df) * 100) if "web.https" in df else 0,
                "google_verify_pct": (df["email_auth.google_verification"].sum() / len(df) * 100) if "email_auth.google_verification" in df else 0,
                "bimi_pct": (df["email_auth.bimi.exists"].sum() / len(df) * 100) if "email_auth.bimi.exists" in df else 0,
                "avg_age_days": df["metadata.age_days"].mean() if "metadata.age_days" in df else 0
            }
            return stats

        best_stats = get_stats(best)
        bad_stats = get_stats(bad)
        
        differences = []
        for key in best_stats:
            diff = best_stats[key] - bad_stats.get(key, 0)
            if abs(diff) > 10: # Significance threshold
                differences.append({
                    "metric": key.replace("_", " ").title().replace("Pct", "%"),
                    "best": best_stats[key],
                    "bad": bad_stats.get(key, 0),
                    "diff": diff
                })
        
        insights = []
        if best_stats.get("avg_score", 0) > bad_stats.get("avg_score", 0) + 10:
            insights.append(f"Best domains have a significantly higher average score ({best_stats['avg_score']:.1f}) than Bad domains.")
        
        if best_stats.get("dmarc_strict_pct", 0) > bad_stats.get("dmarc_strict_pct", 0) + 20:
            insights.append(f"Strict DMARC policies (reject/quarantine) are {best_stats['dmarc_strict_pct'] - bad_stats.get('dmarc_strict_pct', 0):.0f}% more common in the Best group—a key Gmail trust signal.")
        
        if best_stats.get("google_verify_pct", 0) > bad_stats.get("google_verify_pct", 0) + 15:
            insights.append(f"The Best group is {best_stats['google_verify_pct'] - bad_stats.get('google_verify_pct', 0):.0f}% more likely to be integrated with Google services (Search/Postmaster).")

        return {
            "summary": {"best": best_stats, "bad": bad_stats},
            "insights": insights,
            "differences": differences,
            "unique_factors": {}
        }
