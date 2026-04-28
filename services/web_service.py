import httpx
from bs4 import BeautifulSoup

class WebService:
    @staticmethod
    async def analyze_website(domain: str):
        analysis = {
            "status_code": None,
            "final_url": None,
            "https": False,
            "title": None,
            "meta_description": None,
            "links_count": 0,
            "content_length": 0
        }
        
        urls_to_try = [f"https://{domain}", f"http://{domain}"]
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for url in urls_to_try:
                try:
                    response = await client.get(url)
                    analysis["status_code"] = response.status_code
                    analysis["final_url"] = str(response.url)
                    analysis["https"] = str(response.url).startswith("https")
                    analysis["content_length"] = len(response.text)
                    
                    soup = BeautifulSoup(response.text, "html.parser")
                    analysis["title"] = soup.title.string.strip() if soup.title else None
                    
                    desc = soup.find("meta", attrs={"name": "description"})
                    if desc:
                        analysis["meta_description"] = desc.get("content", "").strip()
                    
                    analysis["links_count"] = len(soup.find_all("a"))
                    break # Success
                except Exception:
                    continue
                    
        return analysis
