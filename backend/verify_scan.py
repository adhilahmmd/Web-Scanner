import asyncio
import httpx
import time
import json

BASE_URL = "http://localhost:8000/api/scan"

async def verify():
    async with httpx.AsyncClient(timeout=30) as client:
        # Start async scan
        print("Starting async scan...")
        payload = {
            "url": "http://testphp.vulnweb.com",
            "modules": ["sqli", "xss", "headers"],
            "timeout": 10,
            "use_crawler": True,
            "max_depth": 1,
            "max_pages": 5,
            "scan_all_links": True
        }
        resp = await client.post(f"{BASE_URL}/async", json=payload)
        if resp.status_code != 200:
            print(f"Failed to start scan: {resp.text}")
            return
        
        job_id = resp.json()["job_id"]
        print(f"Job IDs: {job_id}")

        # Poll for status
        for i in range(30):
            status_resp = await client.get(f"{BASE_URL}/{job_id}")
            if status_resp.status_code != 200:
                print(f"Failed to poll status: {status_resp.text}")
                break
            
            job = status_resp.json()
            print(f"[{i}] Status: {job['status']} | Progress: {job.get('progress')}% | Message: {job.get('status_message', 'N/A')}")
            
            if job["status"] == "completed":
                print("Scan completed successfully!")
                # print(json.dumps(job["result"], indent=2))
                break
            elif job["status"] == "failed":
                print(f"Scan failed: {job.get('error')}")
                break
            
            await asyncio.sleep(2)

if __name__ == "__main__":
    asyncio.run(verify())
