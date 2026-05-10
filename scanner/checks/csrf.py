from typing import List, Dict
from scanner.parsers.forms import Form

def check_csrf(forms: List[Form]) -> List[Dict]:
    """
    Detects forms lacking CSRF protection.
    Looks for hidden inputs with names like 'csrf_token' in state-changing forms.
    """
    findings = []
    
    state_changing_methods = ['post', 'put', 'delete', 'patch']
    csrf_patterns = ['csrf_token', '_token', 'authenticity_token', 'csrf']
    
    for form in forms:
        if form.method not in state_changing_methods:
            continue
            
        has_token = False
        for input_field in form.inputs:
            name = input_field.get('name')
            if not name:
                continue
                
            name_lower = name.lower()
            if any(pattern in name_lower for pattern in csrf_patterns):
                has_token = True
                break
                
        if not has_token:
            findings.append({
                "type": "csrf_no_token",
                "action": form.action,
                "msg": f"Form has no CSRF token field (Method: {form.method.upper()})"
            })
            
    return findings
