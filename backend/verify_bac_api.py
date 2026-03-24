
import asyncio
import httpx
import time
import json

BASE_URL = "http://localhost:8000/api/scan"

async def verify_bac():
    async with httpx.AsyncClient(timeout=60) as client:
        print("Starting async BAC scan...")
        payload = {
            "url": "http://testphp.vulnweb.com",
            "modules": ["bac"],
            "timeout": 5,
            "use_crawler": False, # skip crawler for speed
            "max_depth": 1,
            "max_pages": 1,
            "scan_all_links": False
        }
        try:
            resp = await client.post(f"{BASE_URL}/async", json=payload)
            if resp.status_code != 200:
                print(f"Failed to start scan: {resp.text}")
                return
            
            job_id = resp.json()["job_id"]
            print(f"Job ID: {job_id}")

            # Poll for status
            for i in range(60):
                status_resp = await client.get(f"{BASE_URL}/{job_id}")
                if status_resp.status_code != 200:
                    print(f"Failed to poll status: {status_resp.text}")
                    break
                
                job = status_resp.json()
                print(f"[{i}] Status: {job['status']} | Progress: {job.get('progress')}%")
                
                if job["status"] == "completed":
                    print("Scan completed successfully!")
                    result = job.get("result", {})
                    bac_result = result.get("results", {}).get("bac", {})
                    if "error" in bac_result:
                        print(f"BAC Module Error: {bac_result['error']}")
                    else:
                        print(f"BAC Findings: {len(bac_result.get('findings', []))}")
                    break
                elif job["status"] == "failed":
                    print(f"Scan failed: {job.get('error')}")
                    break
                
                await asyncio.sleep(2)
        except Exception as e:
            print(f"Error during verification: {str(e)}")

if __name__ == "__main__":
    asyncio.run(verify_bac())
