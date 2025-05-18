import pandas as pd
import re

# Load your Excel file and create the lookup dictionary
vuln_df = pd.read_excel("vulnerabilities.xlsx")

# Ensure both keys and values are strings and lowercase the keys for matching
replacements_dict = {
    str(name).lower(): str(description)
    for name, description in zip(vuln_df['ZAP Alert Name'], vuln_df['Description'])
    if pd.notna(name) and pd.notna(description)
}

def simplify_explanation(text):
    text_lower = text.lower()

    for term, explanation in replacements_dict.items():
        # Safely escape special regex characters in the term
        pattern = rf'\b{re.escape(term)}\b'
        try:
            text_lower = re.sub(pattern, explanation, text_lower)
        except re.error as e:
            print(f"Regex error with pattern '{pattern}': {e}")
            continue

    return text_lower.capitalize()
