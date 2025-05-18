import pandas as pd
import re

# Load the Excel file once
vuln_df = pd.read_excel("vulnerabilities.xlsx")

# Create a dictionary: key = ZAP Alert Name (lowercased), value = Description
replacements_dict = dict(zip(vuln_df['ZAP Alert Name'].str.lower(), vuln_df['Description']))

def simplify_explanation(text):
    text_lower = text.lower()
    
    # Replace exact matches of vulnerability names in the text with their descriptions
    for term, explanation in replacements_dict.items():
        pattern = rf'\b{re.escape(term)}\b'
        text_lower = re.sub(pattern, explanation, text_lower)
        
    return text_lower.capitalize()
