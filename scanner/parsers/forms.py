import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Optional

class Form:
    def __init__(self, action: str, method: str, inputs: List[Dict[str, Optional[str]]]):
        self.action = action
        self.method = method
        self.inputs = inputs

    def to_dict(self):
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs
        }

def extract_forms(html: str, base_url: str) -> List[Form]:
    """
    Extracts HTML forms from the given HTML document.
    Resolves relative action URLs against the base_url.
    """
    if not html:
        return []

    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        # In case parser completely fails (unlikely with html.parser, but safe to catch)
        return []

    forms = []
    
    for form_tag in soup.find_all('form'):
        # Get action, default to base URL if missing or empty
        action = form_tag.get('action', '').strip()
        if not action:
            resolved_action = base_url
        else:
            resolved_action = urllib.parse.urljoin(base_url, action)
            
        # Get method, default to GET
        method = form_tag.get('method', 'get').strip().lower()
        if method not in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
             method = 'get'

        # Extract input fields
        inputs = []
        
        # Look for standard <input> tags
        for input_tag in form_tag.find_all('input'):
            input_type = input_tag.get('type', 'text').lower()
            input_name = input_tag.get('name')
            
            inputs.append({
                "name": input_name,
                "type": input_type
            })
            
        # Look for <button> elements inside form (often buttons act as submit)
        for button_tag in form_tag.find_all('button'):
            button_type = button_tag.get('type', 'submit').lower()
            button_name = button_tag.get('name')
            inputs.append({
                "name": button_name,
                "type": button_type
            })
            
        # Look for <textarea> elements
        for textarea_tag in form_tag.find_all('textarea'):
            textarea_name = textarea_tag.get('name')
            inputs.append({
                "name": textarea_name,
                "type": "textarea"
            })
            
        # Look for <select> elements
        for select_tag in form_tag.find_all('select'):
             select_name = select_tag.get('name')
             inputs.append({
                 "name": select_name,
                 "type": "select"
             })

        forms.append(Form(resolved_action, method, inputs))

    return forms
