import os
import html
from datetime import datetime
from text_utils import simplify_explanation

def generate_report(alerts, target_url):
    output_dir = "reports"
    os.makedirs(output_dir, exist_ok=True)

    safe_url = target_url.replace(":", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_{safe_url}_{timestamp}.html"
    report_path = os.path.join(output_dir, report_filename)

    unique_terms = get_unique_terms(alerts)
    explanations = {term: simplify_explanation(term) for term in unique_terms}

    report_html = f"""
    <html>
    <head>
        <title>Security Report - {html.escape(target_url)}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 2rem; }}
            .vuln {{ border: 2px solid #ddd; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; }}
            .high {{ border-color: #e74c3c; background-color: #fcebea; }}
            .medium {{ border-color: #f39c12; background-color: #fff6e5; }}
            .low {{ border-color: #3498db; background-color: #eaf3fc; }}
            details {{ margin-top: 0.5rem; }}
        </style>
    </head>
    <body>
        <h1>Security Report for {html.escape(target_url)}</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h3>Total Vulnerabilities Found: {len(alerts)}</h3>
        {"".join([create_vuln_section(v, explanations) for v in alerts])}
    </body>
    </html>
    """

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_html)

    return os.path.abspath(report_path)

def create_vuln_section(vuln, explanations):
    name = html.escape(vuln['name'])
    description = html.escape(vuln['description'])
    solution = html.escape(vuln['solution'])
    severity = float(vuln['severity'])

    if severity >= 7:
        severity_class = "high"
    elif severity >= 4:
        severity_class = "medium"
    else:
        severity_class = "low"

    simplified = html.escape(explanations.get(vuln['name'], "No explanation available."))

    return f"""
    <div class="vuln {severity_class}">
        <h3>{name}</h3>
        <p><strong>Severity:</strong> {severity}/10</p>
        <p>{description}</p>
        <details>
            <summary><strong>Explanation</strong></summary>
            <p>{simplified}</p>
        </details>
        <h4>Recommended Action:</h4>
        <p>{solution}</p>
    </div>
    """

def get_unique_terms(alerts):
    return list({v['name'] for v in alerts})
