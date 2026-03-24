
import asyncio
import sys
import os

# Add the current directory to sys.path to allow imports from subdirectories
sys.path.append(os.path.join(os.getcwd(), 'backend'))

async def test_import():
    try:
        from scanners.bac_scanner import run_bac_scan
        print("Successfully imported run_bac_scan")
        
        # Test a dummy scan (should fail gracefully or run)
        # Note: This might actually try to make network requests if not careful
        # but run_bac_scan takes a list of URLs.
        print("Running a dummy scan...")
        # Use a non-existent local URL to avoid external traffic and catch connection errors
        result = await run_bac_scan(["http://localhost:9999/test"], timeout=1)
        print("Scan completed (reachable or not).")
        print(f"Status: {result.get('status')}")
        if result.get("errors"):
            print(f"Errors found: {result.get('errors')}")
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"FAILED: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_import())
