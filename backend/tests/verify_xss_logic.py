import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from scanners.xss_scanner import payload_reflected

def run_tests():
    test_cases = [
        ("<script>alert(1)</script>", "<html><body><script>alert(1)</script></body></html>", 200, True, "Reflected unencoded (OK)"),
        ("<script>alert(1)</script>", "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>", 200, False, "Reflected encoded (SAFE)"),
        ("<script>alert(1)</script>", "Blocked! <script>alert(1)</script>", 403, True, "Reflected in 403 (HEURISTIC)"),
        ("<script>alert(1)</script>", "Blocked! &lt;script&gt;alert(1)&lt;/script&gt;", 403, False, "Reflected encoded in 403 (SAFE)"),
        ('"><script>alert(1)</script>', "<html><body>&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</body></html>", 200, False, "Reflected encoded with brackets (SAFE)"),
    ]

    print("Running custom XSS verification tests...")
    passed = 0
    for payload, response, status, expected, desc in test_cases:
        actual = payload_reflected(payload, response, status)
        if actual == expected:
            print(f"[PASS] {desc}")
            passed += 1
        else:
            print(f"[FAIL] {desc} | Expected {expected}, got {actual}")
    
    print(f"\nFinal Result: {passed}/{len(test_cases)} tests passed.")
    if passed == len(test_cases):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
