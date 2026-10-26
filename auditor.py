import re
from typing import Dict, Any, List

def audit_server_config(config_type: str, content: str) -> Dict[str, Any]:
    findings = []
    score = 100
    config_type = config_type.lower()
    
    if "nginx" in config_type:
        # Check client_max_body_size
        body_size_match = re.search(r"client_max_body_size\s+([0-9]+)([kmgKMG]?);", content)
        if not body_size_match:
            score -= 35
            findings.append({
                "severity": "CRITICAL",
                "param": "client_max_body_size",
                "issue": "Missing client_max_body_size directive (defaults to unlimited or 1MB without explicit limits).",
                "recommendation": "Add 'client_max_body_size 10M;' in your http or server block."
            })
        else:
            val = int(body_size_match.group(1))
            unit = body_size_match.group(2).upper()
            if (unit == "M" and val > 25) or unit == "G":
                score -= 20
                findings.append({
                    "severity": "WARNING",
                    "param": "client_max_body_size",
                    "issue": f"High body limit configured ({val}{unit}). Allows large multipart exhaustion payloads.",
                    "recommendation": "Restrict body size to 10M unless file uploads strictly require larger."
                })
            else:
                findings.append({
                    "severity": "PASS",
                    "param": "client_max_body_size",
                    "issue": f"Well-configured: {val}{unit} limit active.",
                    "recommendation": "Maintain this configuration."
                })
                
        # Check client_header_buffer_size
        if "client_header_buffer_size" not in content:
            score -= 15
            findings.append({
                "severity": "WARNING",
                "param": "client_header_buffer_size",
                "issue": "Default header buffer allows deep header recursion.",
                "recommendation": "Add 'client_header_buffer_size 1k;'."
            })

    elif "apache" in config_type:
        # Check LimitRequestBody
        limit_match = re.search(r"LimitRequestBody\s+([0-9]+)", content, re.IGNORECASE)
        if not limit_match:
            score -= 40
            findings.append({
                "severity": "CRITICAL",
                "param": "LimitRequestBody",
                "issue": "Missing LimitRequestBody directive. Apache will process unmetered multipart bodies.",
                "recommendation": "Add 'LimitRequestBody 10485760' (10MB) in your VirtualHost block."
            })
        else:
            limit_bytes = int(limit_match.group(1))
            if limit_bytes > 20971520:  # > 20MB
                score -= 20
                findings.append({
                    "severity": "WARNING",
                    "param": "LimitRequestBody",
                    "issue": f"LimitRequestBody allows {limit_bytes // (1024*1024)}MB. Excessively large for standard web forms.",
                    "recommendation": "Lower LimitRequestBody to 10485760 (10MB)."
                })
            else:
                findings.append({
                    "severity": "PASS",
                    "param": "LimitRequestBody",
                    "issue": f"Secure: {limit_bytes // (1024*1024)}MB request cap enforced.",
                    "recommendation": "Configuration complies with Tezhost security guidelines."
                })

    elif "php" in config_type:
        # Check max_input_nesting_level
        nesting_match = re.search(r"max_input_nesting_level\s*=\s*([0-9]+)", content)
        if not nesting_match:
            score -= 30
            findings.append({
                "severity": "WARNING",
                "param": "max_input_nesting_level",
                "issue": "max_input_nesting_level default (64) is close to Assetnote's 62-level exploit threshold.",
                "recommendation": "Add 'max_input_nesting_level = 32' in your php.ini."
            })
        else:
            nesting_val = int(nesting_match.group(1))
            if nesting_val > 48:
                score -= 25
                findings.append({
                    "severity": "WARNING",
                    "param": "max_input_nesting_level",
                    "issue": f"Nesting level is {nesting_val}. High risk of recursive stack pressure.",
                    "recommendation": "Lower max_input_nesting_level to 32."
                })
            else:
                findings.append({
                    "severity": "PASS",
                    "param": "max_input_nesting_level",
                    "issue": f"Safe: Nesting restricted to {nesting_val} levels.",
                    "recommendation": "Excellent protection against PHP2Shell recursion."
                })

    score = max(0, min(100, score))
    status = "SECURE" if score >= 85 else ("MODERATE RISK" if score >= 60 else "HIGH RISK VULNERABLE")
    
    return {
        "score": score,
        "status": status,
        "config_type": config_type,
        "findings": findings
    }

def generate_payload_snippets(depth: int, size_kb: int, boundary: str = "----TezhostSecurityProbe") -> Dict[str, Any]:
    depth = max(1, min(64, depth))
    size_kb = max(10, min(50000, size_kb))
    
    key = "probe" + ("[x]" * depth)
    preview_val = "A" * min(64, size_kb * 1024)
    raw_preview = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
        f"{preview_val}... [Total {size_kb} KB Padding]\r\n"
        f"--{boundary}--\r\n"
    )
    
    curl_cmd = (
        f'# Safe testing command using curl (Depth: {depth}, Size: {size_kb}KB)\n'
        f'python -c "key=\'p\'+\'[x]\'*{depth}; open(\'payload.bin\',\'w\').write(\'X\'*{size_kb}*1024)"\n'
        f'curl -X POST "https://your-domain.com" \\\n'
        f'  -H "Content-Type: multipart/form-data; boundary={boundary}" \\\n'
        f'  -F "{key}=@payload.bin"'
    )
    
    python_script = (
        f"import httpx\n"
        f"# Assetnote-compliant PHP2Shell probe\n"
        f"depth = {depth}\n"
        f"key = 'probe' + ('[x]' * depth)\n"
        f"data = {{key: 'A' * ({size_kb} * 1024)}}\n"
        f"headers = {{'User-Agent': 'Tezhost-PHPScanner/2.4'}}\n\n"
        f"with httpx.Client(timeout=20.0, verify=False) as client:\n"
        f"    response = client.post('https://your-domain.com', data=data, headers=headers)\n"
        f"    print('Status Code:', response.status_code)\n"
        f"    if response.status_code == 500:\n"
        f"        print('Signal: Potential worker exhaustion or crash detected!')\n"
    )

    return {
        "depth": depth,
        "size_kb": size_kb,
        "boundary": boundary,
        "raw_preview": raw_preview,
        "curl_command": curl_cmd,
        "python_script": python_script
    }
