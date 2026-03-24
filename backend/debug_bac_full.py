
import asyncio
import sys
import os

# Add the current directory to sys.path to allow imports from subdirectories
sys.path.append(os.path.join(os.getcwd(), 'backend'))

async def debug_scan():
    try:
        from scanners.bac_scanner import run_bac_scan
        print("Starting full BAC debug scan...")
        
        target_url = "http://testphp.vulnweb.com/userinfo.php?uid=1"
        result = await run_bac_scan([target_url], timeout=5)
        
        print("\nScan Summary:")
        print(f"Status: {result.get('status')}")
        summary = result.get("summary")
        if summary:
            print(f"Total Checks: {summary.total_checks}")
            print(f"Vulnerabilities: {summary.vulnerabilities_found}")
            print(f"Risk Level: {summary.risk_level}")
            
        if result.get("errors"):
            print("\nErrors Found:")
            for err in result["errors"]:
                print(f"- {err}")
                
        if result.get("findings"):
            print(f"\nFindings Found: {len(result['findings'])}")
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRASH: {str(e)}")

if __name__ == "__main__":
    asyncio.run(debug_scan())
