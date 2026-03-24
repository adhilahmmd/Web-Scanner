import sys
import os
import pytest
from unittest.mock import MagicMock

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from scanners.xss_scanner import payload_reflected

def test_payload_reflected_success():
    payload = "<script>alert(1)</script>"
    response_text = "<html><body>Your input: <script>alert(1)</script></body></html>"
    assert payload_reflected(payload, response_text, 200) == True

def test_payload_reflected_encoded_safe():
    payload = "<script>alert(1)</script>"
    response_text = "<html><body>Your input: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    # Even if payload.lower() in response_text.lower() would be true if payload was just "alert",
    # the check for < and &lt; should catch it.
    assert payload_reflected(payload, response_text, 200) == False

def test_payload_reflected_waf_block_page():
    payload = "<script>alert(1)</script>"
    # A common WAF block page echoing the payload
    response_text = "Blocked! Your request contained: <script>alert(1)</script>"
    # For status_code >= 400, it should be more strict. 
    # Current logic flags if <script> and alert are present and NOT encoded.
    # Wait, my logic for >= 400 says:
    # if "<script>" in lower_text and "alert" in lower_text:
    #     if "&lt;script&gt;" not in lower_text:
    #         return True
    
    # Actually, many WAFs DO echo it raw in a 403.
    # But for BookMyShow, it's likely they reflect headers in a 200 (like in a comment) 
    # or they are using a 4xx.
    
    assert payload_reflected(payload, response_text, 403) == True # This is still "Reflected" but in an error page.

def test_header_reflection_in_comment():
    payload = "Mozilla/5.0 <script>alert(1)</script>"
    response_text = "<!-- User-Agent was: Mozilla/5.0 &lt;script&gt;alert(1)&lt;/script&gt; -->"
    assert payload_reflected(payload, response_text, 200) == False

def test_no_reflection():
    payload = "<script>alert(1)</script>"
    response_text = "<html><body>Welcome!</body></html>"
    assert payload_reflected(payload, response_text, 200) == False

def test_generic_script_indicator():
    # Test if it catches manual script tags even if the payload is slightly modified
    payload = "nothing"
    response_text = "<div><script>alert(123)</script></div>"
    assert payload_reflected(payload, response_text, 200) == True
