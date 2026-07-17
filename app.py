"""
Advanced Digital Forensics and Anti-Forensics Detection Toolkit
Flask Web Application
"""

import os
import sys
import json
import base64
import struct
import math
import hashlib
import time
import threading
import subprocess
import re
import io
import numpy as np
import cv2
from PIL import Image
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

REPORT_MODULE_ICONS = {
    'metadata': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect x="3" y="1" width="19" height="26" rx="2" fill="#ede9fe" stroke="#7C3AED" stroke-width="1.5"/><path d="M17 1v7h7" stroke="#7C3AED" stroke-width="1.5" fill="none" stroke-linejoin="round"/><text x="6" y="18" font-size="8" font-family="monospace" font-weight="700" fill="#4F6EF7">&lt;/&gt;</text><circle cx="23" cy="25" r="6" fill="#7C3AED" opacity="0.12" stroke="#7C3AED" stroke-width="1.5"/><path d="M23 22v1.2m0 3.6V28m-3.1-4.9.85.85m4.5 4.5.85.85M20 25h1.2m3.6 0H26m-5.1 1.65.85-.85m4.5-4.5.85-.85" stroke="#7C3AED" stroke-width="1.2" stroke-linecap="round"/><circle cx="23" cy="25" r="1.8" fill="#7C3AED"/></svg>',
    'stego': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect x="2" y="2" width="28" height="28" rx="6" fill="#ecfeff" stroke="#0891B2" stroke-width="1.5"/><ellipse cx="16" cy="16" rx="10" ry="6" stroke="#0891B2" stroke-width="1.8" fill="none"/><circle cx="16" cy="16" r="3.5" fill="#0891B2"/><circle cx="16" cy="16" r="1.5" fill="#ecfeff"/><line x1="6" y1="14" x2="26" y2="14" stroke="#0891B2" stroke-width="1" opacity="0.35"/><line x1="6" y1="18" x2="26" y2="18" stroke="#0891B2" stroke-width="1" opacity="0.35"/></svg>',
    'encoding': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect x="2" y="2" width="28" height="28" rx="6" fill="#ecfdf5" stroke="#059669" stroke-width="1.5"/><text x="4" y="20" font-size="11" font-family="monospace" font-weight="800" fill="#059669">&lt;/&gt;</text><polyline points="22,9 27,16 22,23" stroke="#059669" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    'signature': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect x="3" y="1" width="26" height="30" rx="3" fill="#eef2ff" stroke="#4338CA" stroke-width="1.5"/><path d="M21 1v9h9" stroke="#4338CA" stroke-width="1.5" fill="none" stroke-linejoin="round"/><line x1="7" y1="14" x2="19" y2="14" stroke="#4338CA" stroke-width="1.5" opacity="0.5"/><line x1="7" y1="18" x2="16" y2="18" stroke="#4338CA" stroke-width="1.5" opacity="0.35"/><rect x="3" y="21" width="26" height="10" rx="0" fill="#4338CA"/><path d="M3 28h26v4a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3v-4z" fill="#4338CA"/><text x="16" y="29" font-size="6.5" font-family="monospace" font-weight="800" fill="white" text-anchor="middle">.EXE?</text></svg>',
    'deepfake': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect x="2" y="2" width="28" height="28" rx="6" fill="#fef2f2" stroke="#DC2626" stroke-width="1.5"/><circle cx="16" cy="13" r="5.5" stroke="#DC2626" stroke-width="2" fill="none"/><path d="M7 27c0-4.9 4-9 9-9s9 4.1 9 9" stroke="#DC2626" stroke-width="2" fill="none" stroke-linecap="round"/><line x1="9" y1="10" x2="23" y2="10" stroke="#DC2626" stroke-width="1" opacity="0.4"/><line x1="8" y1="13" x2="10.5" y2="13" stroke="#DC2626" stroke-width="1" opacity="0.4"/><line x1="21.5" y1="13" x2="24" y2="13" stroke="#DC2626" stroke-width="1" opacity="0.4"/><line x1="9" y1="16" x2="23" y2="16" stroke="#DC2626" stroke-width="1" opacity="0.4"/></svg>',
    'report': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect x="3" y="3" width="26" height="26" rx="5" fill="#fff7ed" stroke="#EA580C" stroke-width="1.5"/><rect x="8" y="7" width="16" height="3" rx="1.5" fill="#EA580C" opacity="0.45"/><rect x="8" y="12" width="11" height="2" rx="1" fill="#EA580C" opacity="0.3"/><rect x="8" y="20" width="3.5" height="7" rx="1" fill="#EA580C"/><rect x="14" y="17" width="3.5" height="10" rx="1" fill="#F97316"/><rect x="20" y="14" width="3.5" height="13" rx="1" fill="#FB923C"/><polyline points="9.5,20 15.5,17 21.5,14 25,11" stroke="#EA580C" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>'
}


def _report_module_icon(module_key_or_name, provided_icon=''):
    if isinstance(provided_icon, str) and '<svg' in provided_icon.lower():
        return provided_icon

    key = re.sub(r'[^a-z0-9]+', ' ', str(module_key_or_name or '').lower())
    if 'metadata' in key:
        return REPORT_MODULE_ICONS['metadata']
    if 'stego' in key or 'steganography' in key:
        return REPORT_MODULE_ICONS['stego']
    if 'encoding' in key or 'decoding' in key:
        return REPORT_MODULE_ICONS['encoding']
    if 'signature' in key:
        return REPORT_MODULE_ICONS['signature']
    if 'deepfake' in key:
        return REPORT_MODULE_ICONS['deepfake']
    return REPORT_MODULE_ICONS['report']


# =====================================================
# DEEPFAKE MODEL LOADER
# =====================================================

_MODEL_NAME = "prithivMLmods/Deep-Fake-Detector-v2-Model"
_MODEL_PIPELINE = None
_MODEL_LOCK = threading.Lock()


def get_model():
    global _MODEL_PIPELINE

    if _MODEL_PIPELINE is None:
        with _MODEL_LOCK:
            if _MODEL_PIPELINE is None:
                from transformers import pipeline

                _MODEL_PIPELINE = pipeline(
                    "image-classification",
                    model=_MODEL_NAME,
                    device=-1
                )

    return _MODEL_PIPELINE


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


# ─────────────────────────────────────────────
# API: METADATA (WITH MFT SUPPORT)
# ─────────────────────────────────────────────
@app.route('/api/metadata', methods=['POST'])
def api_metadata():

    f = request.files.get('file')
    mft = request.files.get('mft_file')

    if not f:
        return jsonify({'error': 'No file provided'}), 400

    # ✅ VALIDATE MFT FILE
    if not mft or not is_valid_mft(mft.filename):
        return jsonify({'error': 'Please upload a valid $MFT (.copy0) file'}), 400

    path = _save(f)
    mft_path = _save(mft)

    try:
        result = analyze_metadata(path, f.filename, mft_path, request.form.get('client_last_modified_ms'))
        return jsonify(result)
    finally:
        _cleanup(path)
        _cleanup(mft_path)

@app.route('/api/report/html', methods=['POST'])
def generate_html_report():
    try:
        data = request.get_json()

        title = data.get('title', 'Forensics Analysis Report')
        modules = data.get('modules', [])
        generated_at = datetime.now()
        generated_at_str = generated_at.strftime('%B %d, %Y at %H:%M:%S')
        date_short = generated_at.strftime('%Y-%m-%d')

        # Build verdict summary
        total_modules = len(modules)
        warnings = sum(1 for m in modules if m.get('verdict_type') in ('warning', 'danger') or 'TAMPERING' in str(m.get('verdict', '')).upper())
        successes = sum(1 for m in modules if m.get('verdict_type') == 'success' or ('NO' in str(m.get('verdict', '')).upper() and 'TAMPERING' in str(m.get('verdict', '')).upper()))

        # Determine overall status
        if warnings > 0:
            overall_status = 'warning'
            overall_icon = '⚠'
            overall_title = 'Potential Issues Detected'
            overall_sub = f'{warnings} of {total_modules} modules reported concerns requiring attention'
            status_color = '#D97706'
        else:
            overall_status = 'success'
            overall_icon = '✓'
            overall_title = 'Analysis Complete'
            overall_sub = 'No significant issues detected across all modules'
            status_color = '#059669'

        # Extract file info from first module if available
        file_info = {}
        for m in modules:
            for r in m.get('results', []):
                label = r.get('label', '')
                if 'File' in label or 'Artifact' in label or 'Size' in label:
                    file_info[label] = r.get('value', '')

        report_id = f"DFIR-{generated_at.strftime('%Y%m%d')}-{str(generated_at.timestamp())[-4:]}"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Forensic Report {report_id}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Crimson+Pro:ital,wght@0,400;0,500;0,600;0,700;1,400&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #ffffff;
            --bg-alt: #f8fafc;
            --bg-subtle: #f1f5f9;
            --surface: #ffffff;
            --border: #e2e8f0;
            --border-strong: #cbd5e1;
            --text: #0f172a;
            --text-primary: #1e293b;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --text-subtle: #94a3b8;
            --primary: #1e40af;
            --primary-dark: #1e3a8a;
            --primary-light: #3b82f6;
            --accent: #0369a1;
            --red: #dc2626;
            --red-bg: #fef2f2;
            --red-border: #fecaca;
            --amber: #d97706;
            --amber-bg: #fffbeb;
            --amber-border: #fed7aa;
            --green: #059669;
            --green-bg: #ecfdf5;
            --green-border: #a7f3d0;
            --blue: #2563eb;
            --blue-bg: #eff6ff;
            --blue-border: #bfdbfe;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
            --font-serif: 'Crimson Pro', Georgia, 'Times New Roman', serif;
            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        @page {{
            size: A4;
            margin: 20mm;
        }}

        body {{
            font-family: var(--font-sans);
            background: var(--bg);
            color: var(--text-primary);
            font-size: 10pt;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }}

        .document {{
            max-width: 210mm;
            margin: 0 auto;
            padding: 40px 48px;
            background: var(--bg);
        }}

        /* LETTERHEAD */
        .letterhead {{
            border-bottom: 3px solid var(--primary);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}

        .letterhead-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }}

        .org-brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .org-logo {{
            width: 44px;
            height: 44px;
            background: var(--primary);
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.4rem;
        }}

        .org-info h1 {{
            font-family: var(--font-serif);
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--text);
            letter-spacing: -0.01em;
            line-height: 1.2;
        }}

        .org-info p {{
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 500;
            letter-spacing: 0.02em;
            margin-top: 2px;
        }}

        .report-meta {{
            text-align: right;
        }}

        .report-id {{
            font-family: var(--font-mono);
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--primary);
            letter-spacing: 0.02em;
        }}

        .report-date {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        .classification {{
            display: inline-block;
            padding: 4px 12px;
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            border-radius: 4px;
            font-family: var(--font-mono);
            font-size: 0.65rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-top: 8px;
        }}

        /* DOCUMENT TITLE */
        .doc-title {{
            font-family: var(--font-serif);
            font-size: 1.75rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 8px;
            line-height: 1.3;
        }}

        .doc-subtitle {{
            font-size: 0.95rem;
            color: var(--text-secondary);
            font-weight: 400;
            margin-bottom: 20px;
        }}

        /* CASE INFO BOX */
        .case-info {{
            background: var(--bg-alt);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }}

        .case-info-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px 24px;
        }}

        .case-field {{
            display: flex;
            flex-direction: column;
        }}

        .case-label {{
            font-family: var(--font-mono);
            font-size: 0.65rem;
            font-weight: 600;
            color: var(--text-subtle);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 4px;
        }}

        .case-value {{
            font-size: 0.85rem;
            color: var(--text-primary);
            font-weight: 500;
        }}

        .case-value.mono {{
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        /* EXECUTIVE SUMMARY */
        .executive-summary {{
            background: var(--blue-bg);
            border: 1px solid var(--blue-border);
            border-radius: 6px;
            padding: 20px 24px;
            margin-bottom: 24px;
        }}

        .executive-summary.success {{
            background: var(--green-bg);
            border-color: var(--green-border);
        }}

        .executive-summary.warning {{
            background: var(--amber-bg);
            border-color: var(--amber-border);
        }}

        .executive-summary.critical {{
            background: var(--red-bg);
            border-color: var(--red-border);
        }}

        .summary-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }}

        .summary-badge {{
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 700;
        }}

        .executive-summary.success .summary-badge {{
            background: var(--green);
            color: white;
        }}

        .executive-summary.warning .summary-badge {{
            background: var(--amber);
            color: white;
        }}

        .executive-summary.critical .summary-badge {{
            background: var(--red);
            color: white;
        }}

        .summary-title {{
            font-family: var(--font-serif);
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text);
        }}

        .executive-summary.success .summary-title {{ color: var(--green); }}
        .executive-summary.warning .summary-title {{ color: var(--amber); }}
        .executive-summary.critical .summary-title {{ color: var(--red); }}

        .summary-text {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }}

        /* SECTION HEADERS */
        .section {{
            margin-bottom: 28px;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }}

        .section-number {{
            font-family: var(--font-mono);
            font-size: 0.7rem;
            font-weight: 600;
            color: var(--primary);
            width: 24px;
            height: 24px;
            border: 1.5px solid var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .section-title {{
            font-family: var(--font-serif);
            font-size: 1.15rem;
            font-weight: 600;
            color: var(--text);
            flex: 1;
        }}

        /* METRICS GRID */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}

        .metric-card {{
            background: var(--bg-alt);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }}

        .metric-value {{
            font-family: var(--font-serif);
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text);
            line-height: 1;
        }}

        .metric-card.status .metric-value {{ color: {status_color}; }}
        .metric-card.passed .metric-value {{ color: var(--green); }}
        .metric-card.warnings .metric-value {{ color: var(--amber); }}

        .metric-label {{
            font-family: var(--font-mono);
            font-size: 0.6rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-top: 8px;
        }}

        /* EVIDENCE CARDS */
        .evidence-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            margin-bottom: 16px;
            box-shadow: var(--shadow-sm);
        }}

        .evidence-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 18px;
            background: var(--bg-alt);
            border-bottom: 1px solid var(--border);
            border-radius: 6px 6px 0 0;
        }}

        .evidence-icon {{
            width: 34px;
            height: 34px;
            background: transparent;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}

        .evidence-icon svg {{
            width: 32px;
            height: 32px;
            display: block;
        }}

        .evidence-title-group {{
            flex: 1;
        }}

        .evidence-title {{
            font-family: var(--font-serif);
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
        }}

        .evidence-subtitle {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 1px;
        }}

        .evidence-status {{
            font-family: var(--font-mono);
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            padding: 4px 10px;
            border-radius: 4px;
        }}

        .evidence-status.cleared {{
            background: var(--green-bg);
            color: var(--green);
            border: 1px solid var(--green-border);
        }}

        .evidence-status.suspicious {{
            background: var(--amber-bg);
            color: var(--amber);
            border: 1px solid var(--amber-border);
        }}

        .evidence-status.critical {{
            background: var(--red-bg);
            color: var(--red);
            border: 1px solid var(--red-border);
        }}

        .evidence-body {{
            padding: 0;
        }}

        /* DATA TABLE */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .data-table tr {{
            border-bottom: 1px solid var(--border);
        }}

        .data-table tr:last-child {{
            border-bottom: none;
        }}

        .data-table td {{
            padding: 12px 18px;
            vertical-align: top;
        }}

        .data-label {{
            width: 35%;
            font-family: var(--font-mono);
            font-size: 0.7rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding-top: 14px;
        }}

        .data-value {{
            font-size: 0.9rem;
            color: var(--text-primary);
            line-height: 1.5;
            word-break: break-word;
        }}

        .data-value.mono {{
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--text-secondary);
            background: var(--bg-subtle);
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid var(--border);
            word-break: break-all;
        }}

        .data-value.success {{ color: var(--green); font-weight: 500; }}
        .data-value.warning {{ color: var(--amber); font-weight: 500; }}
        .data-value.critical {{ color: var(--red); font-weight: 500; }}

        /* FINDINGS BOX */
        .findings-box {{
            background: var(--amber-bg);
            border: 1px solid var(--amber-border);
            border-radius: 4px;
            padding: 12px 16px;
            margin: 12px 18px;
        }}

        .findings-box.critical {{
            background: var(--red-bg);
            border-color: var(--red-border);
        }}

        .findings-title {{
            font-family: var(--font-mono);
            font-size: 0.7rem;
            font-weight: 600;
            color: var(--amber);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 8px;
        }}

        .findings-box.critical .findings-title {{ color: var(--red); }}

        .finding-item {{
            display: flex;
            align-items: flex-start;
            gap: 8px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}

        .finding-item:last-child {{ margin-bottom: 0; }}

        .finding-bullet {{
            color: var(--amber);
            font-weight: 600;
            flex-shrink: 0;
        }}

        .findings-box.critical .finding-bullet {{ color: var(--red); }}

        /* FOOTER */
        .document-footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid var(--border);
        }}

        .footer-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }}

        .footer-section h4 {{
            font-family: var(--font-mono);
            font-size: 0.65rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 8px;
        }}

        .footer-section p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }}

        .footer-hash {{
            font-family: var(--font-mono);
            font-size: 0.7rem;
            color: var(--text-subtle);
            word-break: break-all;
        }}

        .disclaimer {{
            margin-top: 20px;
            padding: 12px 16px;
            background: var(--bg-alt);
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--text-muted);
            line-height: 1.5;
            text-align: center;
        }}

        /* Print Styles */
        @media print {{
            body {{ background: white; }}
            .document {{ max-width: 100%; padding: 0; }}
            .evidence-card {{ break-inside: avoid; box-shadow: none; border: 1px solid #ccc; }}
            .executive-summary, .case-info {{ break-inside: avoid; }}
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .document {{ padding: 24px; }}
            .case-info-grid {{ grid-template-columns: 1fr; }}
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .data-label {{ width: 40%; }}
            .footer-grid {{ grid-template-columns: 1fr; }}
            .letterhead-top {{ flex-direction: column; gap: 16px; }}
            .report-meta {{ text-align: left; }}
        }}

        @media (max-width: 480px) {{
            .metrics-grid {{ grid-template-columns: 1fr; }}
            .data-table td {{ display: block; width: 100%; }}
            .data-label {{ padding-bottom: 4px; }}
        }}
    </style>
</head>
<body>
    <div class="document">
        <!-- LETTERHEAD -->
        <header class="letterhead">
            <div class="letterhead-top">
                <div class="org-brand">
                    <div class="org-logo"><svg width="48" height="48" viewBox="0 0 32 32" fill="none"><rect x="2" y="2" width="28" height="28" rx="7" fill="#e8eaff" stroke="#7C3AED" stroke-width="1.3"/><rect x="6.5" y="8.5" width="17" height="12.5" rx="2.4" fill="#f5f3ff" stroke="#7C3AED" stroke-width="1.45"/><path d="M12.5 24h6M15.5 21v3" stroke="#7C3AED" stroke-width="1.45" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 13h5.5M10 16h4M18.5 13.2h1.8M18.5 16h1.8" stroke="#4F6EF7" stroke-width="1.25" stroke-linecap="round"/><circle cx="21" cy="21" r="4.2" fill="#e8eaff" stroke="#4F6EF7" stroke-width="1.55"/><path d="M23.9 23.9L26.5 26.5" stroke="#4F6EF7" stroke-width="1.7" stroke-linecap="round"/><path d="M19.4 21h3.2M21 19.4v3.2" stroke="#7C3AED" stroke-width="1.2" stroke-linecap="round"/><circle cx="21" cy="21" r="1.05" fill="#7C3AED"/></svg></div>
                    <div class="org-info">
                        <h1>Digital Forensics Laboratory</h1>
                        <p>ADFA Forensics Toolkit</p>
                    </div>
                </div>
                <div class="report-meta">
                    <div class="report-id">{report_id}</div>
                    <div class="report-date">{generated_at_str}</div>
                </div>
            </div>
            <h2 class="doc-title">{title}</h2>
        </header>

        <!-- CASE INFORMATION -->
        <div class="case-info">
            <div class="case-info-grid">
                <div class="case-field">
                    <span class="case-label">Report Reference</span>
                    <span class="case-value mono">{report_id}</span>
                </div>
                <div class="case-field">
                    <span class="case-label">Analysis Date</span>
                    <span class="case-value">{generated_at_str}</span>
                </div>
                <div class="case-field">
                    <span class="case-label">Total Modules</span>
                    <span class="case-value">{total_modules} forensic tests</span>
                </div>
                <div class="case-field">
                    <span class="case-label">Status</span>
                    <span class="case-value" style="color: {status_color}; font-weight: 600;">{overall_title}</span>
                </div>
            </div>
        </div>

        <!-- EXECUTIVE SUMMARY -->
        <div class="executive-summary {overall_status}">
            <div class="summary-header">
                <div class="summary-badge">{overall_icon}</div>
                <h3 class="summary-title">Executive Summary</h3>
            </div>
            <p class="summary-text">{overall_sub}. This report documents the findings of automated forensic analysis performed on submitted evidence. {total_modules} distinct forensic examination modules were executed to detect tampering, metadata anomalies, steganographic content, encoding irregularities, and signature validations. {warnings} modules flagged items requiring further investigation.</p>
        </div>

        <!-- METRICS -->
        <div class="section">
            <div class="section-header">
                <span class="section-number">1</span>
                <h3 class="section-title">Analysis Overview</h3>
            </div>
            <div class="metrics-grid">
                <div class="metric-card status">
                    <div class="metric-value">{overall_icon}</div>
                    <div class="metric-label">Overall Status</div>
                </div>
                <div class="metric-card modules">
                    <div class="metric-value">{total_modules}</div>
                    <div class="metric-label">Tests Run</div>
                </div>
                <div class="metric-card passed">
                    <div class="metric-value">{total_modules - warnings}</div>
                    <div class="metric-label">Passed</div>
                </div>
                <div class="metric-card warnings">
                    <div class="metric-value">{warnings}</div>
                    <div class="metric-label">Flagged</div>
                </div>
            </div>
        </div>

        <!-- DETAILED FINDINGS -->
        <div class="section">
            <div class="section-header">
                <span class="section-number">2</span>
                <h3 class="section-title">Detailed Examination Results</h3>
            </div>
"""

        for i, mod in enumerate(modules):
            mod_name = mod.get('name', 'Unknown Module')
            mod_icon = mod.get('icon', '🔍')
            mod_icon = _report_module_icon(mod.get('key') or mod_name, mod.get('icon', ''))
            mod_verdict = mod.get('verdict', '')
            mod_verdict_type = mod.get('verdict_type', 'info')
            results = mod.get('results', [])
            
            # Normalize verdict for DFIR styling
            vtype = 'cleared' if mod_verdict_type == 'success' else 'suspicious' if mod_verdict_type == 'warning' else 'critical' if mod_verdict_type == 'danger' else 'cleared'
            status_text = 'CLEARED' if vtype == 'cleared' else 'SUSPICIOUS' if vtype == 'suspicious' else 'CRITICAL'
            
            html += f"""
            <div class="evidence-card">
                <div class="evidence-header">
                    <div class="evidence-icon">{mod_icon}</div>
                    <div class="evidence-title-group">
                        <div class="evidence-title">{mod_name}</div>
                        <div class="evidence-subtitle">Examination {i+1} of {total_modules} • {mod_verdict}</div>
                    </div>
                    <div class="evidence-status {vtype}">{status_text}</div>
                </div>
                <div class="evidence-body">
                    <table class="data-table">
"""
            
            for r in results:
                label = r.get('label', '')
                value = r.get('value', '')
                rtype = r.get('type', 'info')
                
                value_class = 'data-value'
                if rtype == 'mono' or 'hash' in label.lower() or 'sha' in label.lower() or 'md5' in label.lower():
                    value_class += ' mono'
                elif rtype == 'success':
                    value_class += ' success'
                elif rtype == 'warning':
                    value_class += ' warning'
                elif rtype == 'danger':
                    value_class += ' critical'
                
                html += f"""
                        <tr>
                            <td class="data-label">{label}</td>
                            <td class="{value_class}">{value}</td>
                        </tr>
"""
            
            html += """
                    </table>
                </div>
            </div>
"""

        html += f"""
        </div>

        <!-- DOCUMENT FOOTER -->
        <footer class="document-footer">
            <div class="footer-section" style="text-align: center;">
                <p style="font-size: 0.8rem; color: var(--text-muted);">
                    Report ID: <span class="footer-hash">{report_id}</span> • Generated: {generated_at_str}
                </p>
            </div>
        </footer>
    </div>
</body>
</html>
"""

        from flask import Response
        return Response(
            html,
            mimetype='text/html',
            headers={
                'Content-Disposition': 'attachment; filename=ADFA_Forensics_Report.html'
            }
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def _save(f):
    filename = secure_filename(f.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(path)
    return path


def _cleanup(path):
    try:
        os.remove(path)
    except:
        pass


def _hash_file(path, algo):
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def is_valid_mft(filename):
    return filename.lower().endswith(('.copy0', '.mft'))


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: METADATA ANALYSIS (SEM3 LOGIC - FULL WORKING)
# ─────────────────────────────────────────────────────────────────────────────

import os
import struct
import hashlib
from datetime import datetime


# ─────────────────────────────────────────────
# HASH FUNCTION
# ─────────────────────────────────────────────
def _hash_file(path, algo):
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────
# WINDOWS TIMESTAMP → DATETIME
# ─────────────────────────────────────────────
def _ts(ts):
    return datetime.utcfromtimestamp((ts - 116444736000000000) / 10000000)


def _safe_ts(ts):
    try:
        if not ts:
            return None
        dt = _ts(ts)
        if dt.year < 1601:
            return None
        return dt
    except (OSError, OverflowError, ValueError):
        return None


def _format_dt(dt):
    if not dt:
        return 'Unavailable'
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f').rstrip('0').rstrip('.')


def _client_modified_from_ms(value):
    try:
        if value in (None, ''):
            return None
        ms = float(value)
        if ms <= 0:
            return None
        return datetime.utcfromtimestamp(ms / 1000)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _timestamp_differs(a, b, tolerance_seconds=2):
    if not a or not b:
        return False
    return abs((a - b).total_seconds()) > tolerance_seconds


def _describe_delta(a, b):
    seconds = abs((a - b).total_seconds())
    if seconds >= 86400:
        return f'{seconds / 86400:.1f} days'
    if seconds >= 3600:
        return f'{seconds / 3600:.1f} hours'
    if seconds >= 60:
        return f'{seconds / 60:.1f} minutes'
    return f'{seconds:.1f} seconds'


# ─────────────────────────────────────────────
# FIND FILE RECORD IN MFT (REAL PARSING)
# ─────────────────────────────────────────────
def _find_mft_record(mft_path, target_name):
    target_name = os.path.basename(target_name).lower()
    best = None
    best_score = -1

    with open(mft_path, 'rb') as f:

        while True:
            record = f.read(1024)
            if len(record) < 1024:
                break

            # Valid MFT record
            if record[0:4] != b'FILE':
                continue

            try:
                flags = struct.unpack("<H", record[22:24])[0]
                in_use = bool(flags & 0x01)
                is_dir = bool(flags & 0x02)
                offset = struct.unpack("<H", record[20:22])[0]

                while offset < 1024:

                    attr_type = struct.unpack("<I", record[offset:offset+4])[0]
                    length = struct.unpack("<I", record[offset+4:offset+8])[0]
                    if length <= 0:
                        break

                    if attr_type == 0xFFFFFFFF:
                        break

                    # FILE_NAME attribute
                    if attr_type == 0x30:

                        content_offset = struct.unpack("<H", record[offset+20:offset+22])[0]
                        content_start = offset + content_offset

                        name_len = record[content_start + 64]
                        name_bytes = record[content_start + 66:content_start + 66 + name_len * 2]

                        name = name_bytes.decode('utf-16le', errors='ignore')
                        name_lower = name.lower()

                        exact = name_lower == target_name
                        contains = target_name in name_lower

                        if exact or contains:
                            score = 0
                            if exact:
                                score += 4
                            if in_use:
                                score += 2
                            if not is_dir:
                                score += 1

                            if score > best_score:
                                best_score = score
                                best = record

                    offset += length

            except:
                continue

    return best


# ─────────────────────────────────────────────
# EXTRACT TIMESTAMPS FROM RECORD
# ─────────────────────────────────────────────
def _extract_timestamps(record):

    offset = struct.unpack("<H", record[20:22])[0]

    si = None
    fn = None

    while offset < 1024:

        attr_type = struct.unpack("<I", record[offset:offset+4])[0]
        length = struct.unpack("<I", record[offset+4:offset+8])[0]
        if length <= 0:
            break

        if attr_type == 0xFFFFFFFF:
            break

        non_resident = record[offset+8]
        if non_resident:
            offset += length
            continue

        content_size = struct.unpack("<I", record[offset+16:offset+20])[0]
        content_offset = struct.unpack("<H", record[offset+20:offset+22])[0]
        content_start = offset + content_offset

        # $STANDARD_INFORMATION
        if attr_type == 0x10 and content_size >= 32:
            si = struct.unpack("<QQQQ", record[content_start:content_start+32])

        # $FILE_NAME
        if attr_type == 0x30 and content_size >= 66:
            candidate = struct.unpack("<QQQQ", record[content_start+8:content_start+40])
            namespace = record[content_start + 65]
            if fn is None or namespace in (1, 3):
                fn = candidate

        offset += length

    return si, fn


# ─────────────────────────────────────────────
# MAIN METADATA FUNCTION
# ─────────────────────────────────────────────
def analyze_metadata(path, filename, mft_path, client_last_modified_ms=None):

    results = []

    try:
        file_size = os.path.getsize(path)
        mft_size = os.path.getsize(mft_path)
        client_modified = _client_modified_from_ms(client_last_modified_ms)

        # HEADER
        results.append({'label': '[METADATA ANALYSIS MODULE]', 'value': '', 'type': 'section'})
        results.append({'label': 'Artifact Type', 'value': 'MFT', 'type': 'info'})
        results.append({'label': 'Artifact File', 'value': os.path.basename(mft_path), 'type': 'info'})
        results.append({'label': 'Suspicious File', 'value': filename, 'type': 'info'})

        # FILE VERIFICATION
        results.append({'label': 'Artifact Size', 'value': f'{mft_size:,} bytes', 'type': 'info'})
        results.append({'label': 'File Size', 'value': f'{file_size:,} bytes', 'type': 'info'})
        if client_modified:
            results.append({'label': 'Uploaded File Modified', 'value': _format_dt(client_modified), 'type': 'info'})

        # ─────────────────────────────────────────────
        # FIND RECORD
        # ─────────────────────────────────────────────
        record = _find_mft_record(mft_path, filename)

        if not record:
            results.append({'label': '⚠ MFT Analysis', 'value': 'File not found in $MFT', 'type': 'warning'})
        else:
            results.append({'label': 'MFT Record', 'value': 'File found in MFT', 'type': 'success'})

            si, fn = _extract_timestamps(record)

            if si and fn:

                si_times = {
                    'Created': _safe_ts(si[0]),
                    'Modified': _safe_ts(si[1]),
                    'Accessed': _safe_ts(si[3])
                }
                fn_times = {
                    'Created': _safe_ts(fn[0]),
                    'Modified': _safe_ts(fn[1]),
                    'Accessed': _safe_ts(fn[3])
                }

                for label in ('Created', 'Modified', 'Accessed'):
                    results.append({'label': f'MFT $SI {label}', 'value': _format_dt(si_times[label]), 'type': 'info'})

                for label in ('Created', 'Modified', 'Accessed'):
                    results.append({'label': f'MFT $FN {label}', 'value': _format_dt(fn_times[label]), 'type': 'info'})

                findings = []

                # ─────────────────────────────────────────────
                # VERDICT (SEM3 LOGIC)
                # ─────────────────────────────────────────────
                if client_modified:
                    for source, times in (('$SI', si_times), ('$FN', fn_times)):
                        mft_modified = times['Modified']
                        if _timestamp_differs(client_modified, mft_modified):
                            findings.append(
                                f'Uploaded file Modified time differs from MFT {source} Modified by '
                                f'{_describe_delta(client_modified, mft_modified)}'
                            )

                for label in ('Created', 'Modified', 'Accessed'):
                    if _timestamp_differs(si_times[label], fn_times[label]):
                        findings.append(
                            f'MFT $STANDARD_INFORMATION and $FILE_NAME {label} differ by '
                            f'{_describe_delta(si_times[label], fn_times[label])}'
                        )

                now = datetime.utcnow()
                for source, times in (('$SI', si_times), ('$FN', fn_times)):
                    created = times['Created']
                    modified = times['Modified']
                    accessed = times['Accessed']

                    if created and created > now:
                        findings.append(f'MFT {source} Created timestamp is in the future')
                    if modified and modified > now:
                        findings.append(f'MFT {source} Modified timestamp is in the future')
                    if accessed and accessed > now:
                        findings.append(f'MFT {source} Accessed timestamp is in the future')
                    if created and modified and modified < created:
                        findings.append(f'MFT {source} Modified timestamp is earlier than Created')
                    if created and accessed and accessed < created:
                        findings.append(f'MFT {source} Accessed timestamp is earlier than Created')
                    if accessed and accessed.year < 1980:
                        findings.append(f'MFT {source} Accessed timestamp is unusually old')

                if findings:
                    for finding in dict.fromkeys(findings):
                        results.append({'label': 'Tamper Evidence', 'value': finding, 'type': 'warning'})
                    verdict = "TIMESTAMP TAMPERING DETECTED"
                    vtype = "warning"
                else:
                    verdict = "NO TIMESTAMP TAMPERING DETECTED"
                    vtype = "success"

                results.append({'label': 'FORENSIC VERDICT', 'value': verdict, 'type': vtype})

            else:
                results.append({'label': '⚠ Error', 'value': 'Timestamp extraction failed', 'type': 'warning'})

        # ─────────────────────────────────────────────
        # HASHES
        # ─────────────────────────────────────────────
        results.append({'label': 'SHA-256', 'value': _hash_file(path, 'sha256'), 'type': 'mono'})
        results.append({'label': 'MD5', 'value': _hash_file(path, 'md5'), 'type': 'mono'})

        # Determine top-level verdict from results
        verdict_row = next((r for r in results if r.get('label') == 'FORENSIC VERDICT'), None)
        top_verdict = verdict_row['value'] if verdict_row else 'Analysis Complete'
        top_vtype   = verdict_row['type']  if verdict_row else 'info'

        return {
            'status': 'success',
            'filename': filename,
            'verdict': top_verdict,
            'verdict_type': top_vtype,
            'results': results
        }

    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

# ─────────────────────────────────────────────────────────────────────────────
# MODULE: STEGANOGRAPHY — IMAGE
# ─────────────────────────────────────────────────────────────────────────────

def _get_exiftool_path():
    """Get the path to exiftool - check bundled first, then system."""
    # Check for bundled exiftool.exe in tools directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bundled_exiftool = os.path.join(script_dir, 'tools', 'exiftool.exe')
    if os.path.exists(bundled_exiftool):
        return bundled_exiftool
    # Fall back to system exiftool
    return 'exiftool'

def _get_exif_with_pil(path):
    """Use PIL to extract metadata from images including PNG text chunks."""
    exif_results = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(path)
        
        # Basic image info
        exif_results.append({'label': 'EXIF: Format', 'value': img.format or 'Unknown', 'type': 'exif'})
        exif_results.append({'label': 'EXIF: Width', 'value': str(img.width), 'type': 'exif'})
        exif_results.append({'label': 'EXIF: Height', 'value': str(img.height), 'type': 'exif'})
        exif_results.append({'label': 'EXIF: Mode', 'value': img.mode, 'type': 'exif'})
        
        # Try to get EXIF data
        try:
            exif = img._getexif() if hasattr(img, '_getexif') else None
            if exif:
                priority_tags = ['Make', 'Model', 'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
                                 'GPSInfo', 'LensModel', 'FNumber', 'ExposureTime', 'ISOSpeedRatings',
                                 'FocalLength', 'Flash', 'Software', 'Artist', 'Copyright',
                                 'ImageDescription', 'UserComment', 'XResolution', 'YResolution']
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    if tag in priority_tags:
                        if tag == 'GPSInfo':
                            # Handle GPS info specially
                            try:
                                gps_data = {}
                                for gps_tag_id, gps_value in value.items():
                                    gps_tag = TAGS.get(gps_tag_id, str(gps_tag_id))
                                    gps_data[gps_tag] = gps_value
                                if gps_data:
                                    exif_results.append({'label': 'EXIF: GPSInfo', 'value': str(gps_data), 'type': 'exif'})
                            except:
                                exif_results.append({'label': 'EXIF: GPSInfo', 'value': str(value)[:200], 'type': 'exif'})
                        elif tag in ['MakerNote', 'PrintImageMatching']:
                            continue  # Skip binary data
                        else:
                            exif_results.append({'label': f'EXIF: {tag}', 'value': str(value)[:200], 'type': 'exif'})
                # Add any other non-priority tags (limited)
                other_count = 0
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    if tag not in priority_tags and tag not in ['MakerNote', 'PrintImageMatching']:
                        if other_count < 15:
                            exif_results.append({'label': f'EXIF: {tag}', 'value': str(value)[:150], 'type': 'exif'})
                            other_count += 1
            else:
                exif_results.append({'label': 'EXIF: Note', 'value': 'No EXIF metadata in image', 'type': 'info'})
        except Exception as e:
            exif_results.append({'label': 'EXIF: Note', 'value': f'No standard EXIF data', 'type': 'info'})
        
        # PNG text chunks and other metadata
        if hasattr(img, 'info') and img.info:
            text_chunks = []
            for key, value in img.info.items():
                if key not in ['exif', 'Exif'] and not key.startswith('icc'):
                    if isinstance(value, (str, int, float)):
                        text_chunks.append(f"{key}: {str(value)[:100]}")
                    elif isinstance(value, bytes) and len(value) < 500:
                        try:
                            decoded = value.decode('utf-8', errors='ignore')[:100]
                            if decoded:
                                text_chunks.append(f"{key}: {decoded}")
                        except:
                            pass
            if text_chunks:
                exif_results.append({'label': 'EXIF: PNG/Text Chunks', 'value': ' | '.join(text_chunks[:5]), 'type': 'exif'})
        
    except ImportError:
        exif_results.append({'label': 'EXIF', 'value': 'PIL not installed', 'type': 'warning'})
    except Exception as e:
        exif_results.append({'label': 'EXIF: Error', 'value': f'PIL error: {str(e)[:100]}', 'type': 'warning'})
    return exif_results

def _get_exif_with_library(path):
    """Use the exif Python library to read EXIF metadata (for JPEG/TIFF)."""
    exif_results = []
    try:
        from exif import Image as ExifImage
        with open(path, 'rb') as f:
            img = ExifImage(f)
        if not img.has_exif:
            return exif_results  # Return empty, PIL will handle it
        
        # Comprehensive tag mapping
        tag_map = {
            # Camera info
            'make': 'Make',
            'model': 'Model',
            'lens_model': 'LensModel',
            'body_serial_number': 'BodySerialNumber',
            'lens_serial_number': 'LensSerialNumber',
            # Dates
            'datetime_original': 'DateTimeOriginal',
            'datetime_digitized': 'DateTimeDigitized',
            'datetime': 'DateTime',
            'gps_datestamp': 'GPSDateStamp',
            # GPS
            'gps_latitude': 'GPSLatitude',
            'gps_longitude': 'GPSLongitude',
            'gps_altitude': 'GPSAltitude',
            'gps_latitude_ref': 'GPSLatitudeRef',
            'gps_longitude_ref': 'GPSLongitudeRef',
            'gps_altitude_ref': 'GPSAltitudeRef',
            'gps_img_direction': 'GPSImgDirection',
            # Camera settings
            'f_number': 'FNumber',
            'exposure_time': 'ExposureTime',
            'iso': 'ISOSpeedRatings',
            'focal_length': 'FocalLength',
            'focal_length_in_35mm_film': 'FocalLengthIn35mmFilm',
            'flash': 'Flash',
            'metering_mode': 'MeteringMode',
            'exposure_program': 'ExposureProgram',
            'exposure_mode': 'ExposureMode',
            'white_balance': 'WhiteBalance',
            'scene_capture_type': 'SceneCaptureType',
            # Software/Creator
            'software': 'Software',
            'artist': 'Artist',
            'copyright': 'Copyright',
            'image_description': 'ImageDescription',
            'user_comment': 'UserComment',
            # Image dimensions
            'image_width': 'ImageWidth',
            'image_height': 'ImageHeight',
            'x_resolution': 'XResolution',
            'y_resolution': 'YResolution',
            'resolution_unit': 'ResolutionUnit',
            'orientation': 'Orientation',
            'bits_per_sample': 'BitsPerSample',
            'color_space': 'ColorSpace',
            'ycbcr_positioning': 'YCbCrPositioning',
            # Compression/Format
            'compression': 'Compression',
            'jpeg_interchange_format': 'JPEGInterchangeFormat',
            'jpeg_interchange_format_length': 'JPEGInterchangeFormatLength',
        }
        
        for attr, label in tag_map.items():
            try:
                value = getattr(img, attr, None)
                if value is not None:
                    if isinstance(value, tuple):
                        value = str(value)
                    exif_results.append({'label': f'EXIF: {label}', 'value': str(value)[:200], 'type': 'exif'})
            except:
                pass
        
        # Add other available attributes
        other_count = 0
        for attr in dir(img):
            if not attr.startswith('_') and attr not in tag_map and not callable(getattr(img, attr)):
                try:
                    val = getattr(img, attr)
                    if val and not attr.startswith('get_'):
                        if other_count < 10 and attr not in ['delete', 'has_exif', 'list_all']:
                            if isinstance(val, (str, int, float, tuple)):
                                exif_results.append({'label': f'EXIF: {attr}', 'value': str(val)[:150], 'type': 'exif'})
                                other_count += 1
                except:
                    pass
    except ImportError:
        pass  # PIL fallback will handle it
    except Exception:
        pass  # PIL fallback will handle it
    return exif_results

def _run_exiftool(path):
    """Run exiftool on the file and return parsed metadata results.
    Uses exiftool binary if available, otherwise falls back to exif Python library."""
    exif_results = []
    exiftool_path = _get_exiftool_path()
    is_bundled = exiftool_path != 'exiftool'

    # Try exiftool binary first
    try:
        result = subprocess.run(
            [exiftool_path, '-json', path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            if data and len(data) > 0:
                metadata = data[0]
                # Add key metadata fields
                priority_fields = [
                    'FileType', 'ImageWidth', 'ImageHeight', 'MIMEType',
                    'Make', 'Model', 'DateTimeOriginal', 'CreateDate', 'ModifyDate',
                    'GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'Software',
                    'Artist', 'Copyright', 'Title', 'Description', 'Comment'
                ]
                for field in priority_fields:
                    if field in metadata and metadata[field]:
                        label = f'EXIF: {field}'
                        value = str(metadata[field])
                        exif_results.append({'label': label, 'value': value, 'type': 'exif'})
                # Add any other fields not in priority list (limited to avoid spam)
                other_count = 0
                for key, val in metadata.items():
                    if key not in priority_fields and not key.startswith('File') and val:
                        if other_count < 10:  # Limit additional fields
                            exif_results.append({'label': f'EXIF: {key}', 'value': str(val)[:100], 'type': 'exif'})
                            other_count += 1
                return exif_results
    except FileNotFoundError:
        pass  # Fall through to library method
    except Exception:
        pass  # Fall through to library method

    # Fallback to PIL for comprehensive metadata (works with PNG, JPEG, etc.)
    exif_results = _get_exif_with_pil(path)
    
    # Also try the exif library for JPEG-specific data and merge results
    try:
        from exif import Image as ExifImage
        with open(path, 'rb') as f:
            img = ExifImage(f)
        if img.has_exif:
            # Add any unique fields from exif library that PIL didn't capture
            existing_labels = {r['label'] for r in exif_results}
            extra_results = _get_exif_with_library(path)
            for item in extra_results:
                if item['label'] not in existing_labels:
                    exif_results.append(item)
    except:
        pass  # PIL results are sufficient
    
    return exif_results

def _analyze_png_chunks(path):
    """Analyze PNG chunk structure for anomalies."""
    results = []
    findings = []
    try:
        with open(path, 'rb') as f:
            header = f.read(8)
            if header != b'\x89PNG\r\n\x1a\n':
                return results, findings
            
            results.append({'label': 'PNG: Signature', 'value': 'Valid PNG signature', 'type': 'success'})
            
            chunks = []
            chunk_count = 0
            critical_chunks = [b'IHDR', b'PLTE', b'IDAT', b'IEND']
            ancillary_chunks = [b'tRNS', b'gAMA', b'cHRM', b'sRGB', b'iCCP', b'tEXt', b'zTXt', b'iTXt', b'bKGD', b'pHYs', b'sBIT', b'hIST', b'tIME']
            
            while True:
                length_bytes = f.read(4)
                if len(length_bytes) < 4:
                    break
                length = struct.unpack('>I', length_bytes)[0]
                chunk_type = f.read(4)
                if len(chunk_type) < 4:
                    break
                chunk_count += 1
                
                # Read chunk data
                if length > 0:
                    data = f.read(length)
                    if len(data) < length:
                        break
                else:
                    data = b''
                
                # Read CRC
                crc = f.read(4)
                if len(crc) < 4:
                    break
                
                chunks.append(chunk_type.decode('ascii', errors='ignore'))
                
                # Check for suspicious chunks
                if chunk_type not in critical_chunks and chunk_type not in ancillary_chunks:
                    chunk_name = chunk_type.decode('ascii', errors='ignore')
                    findings.append(f'Suspicious PNG chunk: {chunk_name}')
                    results.append({'label': f'⚠ PNG Chunk: {chunk_name}', 'value': f'Non-standard chunk (length: {length}) - possible steganography', 'type': 'warning'})
                
                # Check tEXt/zTXt/iTXt chunks for hidden data
                if chunk_type in [b'tEXt', b'zTXt', b'iTXt'] and length > 0:
                    try:
                        text_data = data.decode('latin-1', errors='ignore')
                        if text_data:
                            results.append({'label': f'PNG: {chunk_type.decode()}', 'value': text_data[:200], 'type': 'exif'})
                    except:
                        pass
                
                if chunk_type == b'IEND':
                    break
            
            results.insert(1, {'label': 'PNG: Total Chunks', 'value': str(chunk_count), 'type': 'info'})
            
            # Check for data after IEND (appended payload)
            remaining = f.read()
            if remaining:
                findings.append(f'Data found after IEND chunk ({len(remaining)} bytes) - possible appended payload')
                results.append({'label': '⚠ PNG: Post-IEND Data', 'value': f'{len(remaining):,} bytes after IEND - possible hidden payload', 'type': 'warning'})
            else:
                results.append({'label': 'PNG: Structure', 'value': 'All chunks are standard PNG chunks', 'type': 'success'})
                
    except Exception as e:
        results.append({'label': 'PNG: Error', 'value': str(e), 'type': 'warning'})
    
    return results, findings

def _extract_strings(path, min_length=4, max_strings=50):
    """Extract printable strings from binary file."""
    results = []
    findings = []
    try:
        with open(path, 'rb') as f:
            data = f.read()
        
        # Find printable strings
        strings = re.findall(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}', data)
        decoded = [s.decode('latin-1') for s in strings]
        
        # Filter interesting strings
        interesting = [s for s in decoded if len(s) > 8 and not s.isdigit()]
        
        total_strings = len(decoded)
        results.append({'label': 'Total Strings', 'value': str(total_strings), 'type': 'info'})
        
        if interesting:
            for i, s in enumerate(interesting[:max_strings]):
                results.append({'label': f'String {i+1}', 'value': s[:100], 'type': 'mono'})
            if len(interesting) > max_strings:
                results.append({'label': 'Strings: Note', 'value': f'... and {len(interesting) - max_strings} more strings', 'type': 'info'})
        else:
            results.append({'label': 'Strings', 'value': 'No suspicious strings detected', 'type': 'success'})
            
    except Exception as e:
        results.append({'label': 'Strings: Error', 'value': str(e), 'type': 'warning'})
    
    return results, findings

def _file_entropy(path):
    """Calculate Shannon entropy of entire file."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        from collections import Counter
        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        return entropy
    except:
        return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES: STEGANOGRAPHY
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/steganography/image', methods=['POST'])
def api_stego_image():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file provided'}), 400
    path = _save(f)
    try:
        result = analyze_stego_image(path)
        return jsonify(result)
    finally:
        _cleanup(path)


def analyze_stego_image(path):
    results = []
    filename = os.path.basename(path)
    size = os.path.getsize(path)
    findings = []
    
    # Header
    results.append({'label': 'File', 'value': filename, 'type': 'info'})
    results.append({'label': 'Path', 'value': path, 'type': 'info'})
    results.append({'label': 'Size', 'value': f'{size:,} bytes ({size/1024:.2f} KB)', 'type': 'info'})
    
    # ═════════════════════════════════════════════════════════════════════════════
    # EXIF METADATA ANALYSIS
    # ═════════════════════════════════════════════════════════════════════════════
    exif_results = _run_exiftool(path)
    if exif_results:
        results.extend(exif_results)
    else:
        results.append({'label': 'EXIF', 'value': 'No metadata found', 'type': 'info'})
    
    # ═════════════════════════════════════════════════════════════════════════════
    # FILE HASH ANALYSIS
    # ═════════════════════════════════════════════════════════════════════════════
    md5_hash = _hash_file(path, 'md5')
    sha1_hash = _hash_file(path, 'sha1')
    sha256_hash = _hash_file(path, 'sha256')
    results.append({'label': 'MD5', 'value': md5_hash, 'type': 'mono'})
    results.append({'label': 'SHA1', 'value': sha1_hash, 'type': 'mono'})
    results.append({'label': 'SHA256', 'value': sha256_hash, 'type': 'mono'})
    results.append({'label': 'Note', 'value': 'Use these hashes to verify file integrity', 'type': 'info'})
    
    # ═════════════════════════════════════════════════════════════════════════════
    # FILE HEADER VALIDATION
    # ═════════════════════════════════════════════════════════════════════════════
    ext = os.path.splitext(filename)[1].lower()
    with open(path, 'rb') as f:
        header = f.read(16)
    header_hex = header[:8].hex().upper()
    results.append({'label': 'File Extension', 'value': ext or 'none', 'type': 'info'})
    results.append({'label': 'Header Bytes', 'value': header_hex, 'type': 'mono'})
    detected = _detect_magic(header)
    if detected:
        results.append({'label': 'Detected Type', 'value': detected, 'type': 'info'})
        if ext and ext[1:] not in detected.lower():
            findings.append(f'Extension mismatch: .{ext[1:]} vs detected {detected}')
            results.append({'label': '⚠ Header Validation', 'value': f'Extension {ext} does NOT match detected type: {detected}', 'type': 'warning'})
        else:
            results.append({'label': '✓ Header Validation', 'value': 'Header matches file extension', 'type': 'success'})
    
    # ═════════════════════════════════════════════════════════════════════════════
    # ENTROPY ANALYSIS
    # ═════════════════════════════════════════════════════════════════════════════
    file_entropy = _file_entropy(path)
    results.append({'label': 'File Entropy', 'value': f'{file_entropy:.4f} (scale 0-8)', 'type': 'info'})
    results.append({'label': 'File Size', 'value': f'{size:,} bytes', 'type': 'info'})
    if file_entropy > 7.9:
        findings.append(f'Very high file entropy ({file_entropy:.4f}) - strong indicator of encryption or steganography')
        results.append({'label': '⚠ Entropy Alert', 'value': 'VERY HIGH ENTROPY! Strong indicator of encryption or steganography', 'type': 'warning'})
    elif file_entropy > 7.5:
        findings.append(f'High file entropy ({file_entropy:.4f}) - possible encrypted/compressed data')
        results.append({'label': '⚠ Entropy Alert', 'value': 'High entropy - possible encrypted/compressed data', 'type': 'warning'})
    else:
        results.append({'label': '✓ Entropy', 'value': 'Normal entropy level', 'type': 'success'})
    
    # PNG specific analysis
    ext_lower = ext.lower()
    if ext_lower == '.png' or header[:4] == b'\x89PNG':
        # ═════════════════════════════════════════════════════════════════════════════
        # PNG CHUNK ANALYSIS
        # ═════════════════════════════════════════════════════════════════════════════
        png_results, png_findings = _analyze_png_chunks(path)
        results.extend(png_results)
        findings.extend(png_findings)
    
    # Image analysis (using PIL)
    try:
        from PIL import Image
        import numpy as np
        
        img = Image.open(path)
        img_width, img_height = img.width, img.height
        total_pixels = img_width * img_height
        
        # ═════════════════════════════════════════════════════════════════════════════
        # LSB (LEAST SIGNIFICANT BIT) ANALYSIS
        # ═════════════════════════════════════════════════════════════════════════════
        results.append({'label': 'Image Dimensions', 'value': f'{img_width} × {img_height}', 'type': 'info'})
        results.append({'label': 'Total Pixels', 'value': f'{total_pixels:,}', 'type': 'info'})
        
        arr = np.array(img.convert('RGB'))
        
        # LSB Entropy calculation (sample first 2000 pixels for speed)
        sample_size = min(2000, total_pixels)
        flat_sample = arr[:sample_size // img_width + 1, :, 0].flatten()[:sample_size]
        lsb_sample = flat_sample & 1
        lsb_entropy = _np_entropy(lsb_sample)
        
        results.append({'label': 'LSB Entropy', 'value': f'{lsb_entropy:.4f}', 'type': 'info'})
        if lsb_entropy > 0.95:
            findings.append(f'High LSB entropy ({lsb_entropy:.4f}) - possible hidden data in LSB')
            results.append({'label': '⚠ LSB Entropy', 'value': 'High LSB entropy - possible hidden data', 'type': 'warning'})
        
        # LSB Distribution
        lsb = arr & 1
        lsb_ratio = lsb.mean()
        if abs(lsb_ratio - 0.5) < 0.02:
            findings.append(f'LSB plane shows near-uniform distribution (ratio={lsb_ratio:.4f}) - possible LSB steganography')
            results.append({'label': '⚠ LSB Distribution', 'value': f'Ratio={lsb_ratio:.4f} — suspicious uniformity (threshold ±0.02 of 0.5)', 'type': 'warning'})
        else:
            results.append({'label': '✓ LSB Distribution', 'value': f'Ratio={lsb_ratio:.4f} — normal', 'type': 'success'})
        
        # Chi-Square test on LSB
        from collections import Counter
        flat_lsb = (arr[:,:,0] & 1).flatten()
        c = Counter(flat_lsb)
        chi = abs(c[0] - c[1]) / max(1, (c[0] + c[1]) / 2) * 100
        if chi < 2.0:
            findings.append(f'Chi-square anomaly: very low divergence ({chi:.2f}%) — abnormally balanced LSB pairs (stego indicator)')
            results.append({'label': '⚠ Chi-Square', 'value': f'{chi:.2f}% divergence — abnormally balanced LSB pairs (stego indicator)', 'type': 'warning'})
        else:
            results.append({'label': '✓ Chi-Square', 'value': f'{chi:.2f}% divergence — normal', 'type': 'success'})
        
        # Image entropy
        flat = arr.flatten()
        img_entropy = _np_entropy(flat)
        results.append({'label': 'Image Data Entropy', 'value': f'{img_entropy:.4f} bits/byte', 'type': 'info'})
        if img_entropy > 7.8:
            findings.append(f'High image entropy ({img_entropy:.4f}) - possible hidden encrypted payload')
            results.append({'label': '⚠ Image Entropy Alert', 'value': 'High entropy may indicate hidden encrypted data', 'type': 'warning'})
        
        # File size vs image capacity
        img_capacity = img_width * img_height * 3 // 8
        if size > img_capacity * 1.15:
            findings.append(f'File size exceeds expected image data ({size:,}B > {img_capacity:,}B) — possible appended payload')
            results.append({'label': '⚠ Size Anomaly', 'value': f'File {size:,}B > expected {img_capacity:,}B (excess: {size-img_capacity:,}B)', 'type': 'warning'})
            
    except Exception as e:
        results.append({'label': 'Image Analysis Error', 'value': str(e), 'type': 'warning'})
    
    # ═════════════════════════════════════════════════════════════════════════════
    # STRINGS EXTRACTION
    # ═════════════════════════════════════════════════════════════════════════════
    results.append({'label': '', 'value': 'Strings Extraction', 'type': 'section'})
    strings_results, strings_findings = _extract_strings(path)
    if strings_results:
        results.extend(strings_results)
    else:
        results.append({'label': 'Strings', 'value': 'No strings found', 'type': 'info'})
    findings.extend(strings_findings)
    
    # ═════════════════════════════════════════════════════════════════════════════
    # VERDICT
    # ═════════════════════════════════════════════════════════════════════════════
    results.append({'label': '', 'value': 'Analysis Summary', 'type': 'section'})
    if findings:
        results.append({'label': f'⚠ Found {len(findings)} suspicious indicator(s)!', 'value': '│ ' + ' │ '.join(findings[:3]), 'type': 'warning'})
        verdict = f'SUSPICIOUS — {len(findings)} steganography indicator(s) detected'
        vtype = 'warning'
    else:
        results.append({'label': '✓ Analysis Complete', 'value': 'No steganography indicators found', 'type': 'success'})
        verdict = 'LIKELY CLEAN — No steganography detected'
        vtype = 'success'
    
    return {
        'status': 'success',
        'filename': filename,
        'findings': findings,
        'verdict': verdict,
        'verdict_type': vtype,
        'results': results
    }


def _np_entropy(data):
    import numpy as np
    _, counts = np.unique(data, return_counts=True)
    probs = counts / counts.sum()
    return float(-np.sum(probs * np.log2(probs + 1e-10)))


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: STEGANOGRAPHY — VIDEO
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# MODULE: ENCODING / DECODING
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/encoding', methods=['POST'])
def api_encoding():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file provided'}), 400
    encoding = request.form.get('encoding', 'base64')
    mode = request.form.get('mode', 'encode')
    path = _save(f)
    try:
        result = run_encoding(path, encoding, mode)
        return jsonify(result)
    finally:
        _cleanup(path)


def run_encoding(path, encoding, mode):
    filename = os.path.basename(path)
    with open(path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    enc_label = encoding.upper()

    try:
        if mode == 'encode':
            if encoding == 'base32':
                encoded = base64.b32encode(data)
            else:
                encoded = base64.b64encode(data)

            out_size = len(encoded)
            increase = ((out_size / file_size) - 1) * 100 if file_size else 0
            preview = encoded[:200].decode('ascii', errors='ignore')

            charset = 'A–Z, 2–7 only (32 chars + padding =)' if encoding == 'base32' else 'A–Z, a–z, 0–9, +, / (64 chars + padding =)'
            enc_results = [
                {'label': 'Standard',      'value': enc_label,                              'type': 'info'},
                {'label': 'Operation',     'value': 'Encode (Binary → Text)',                'type': 'info'},
                {'label': 'Input Size',    'value': f'{file_size:,} bytes',                  'type': 'info'},
                {'label': 'Output Size',   'value': f'{out_size:,} bytes',                   'type': 'info'},
                {'label': 'Size Change',   'value': f'+{increase:.1f}%',                     'type': 'warning'},
                {'label': 'Character Set', 'value': charset,                                 'type': 'mono'},
                {'label': 'Output Preview','value': preview + ('...' if len(encoded) > 200 else ''), 'type': 'mono'},
            ]
            return {
                'status': 'success',
                'mode': 'encode',
                'encoding': enc_label,
                'filename': filename,
                'verdict': f'{enc_label} Encoding Complete',
                'verdict_type': 'success',
                'input_size': f'{file_size:,} bytes',
                'output_size': f'{out_size:,} bytes',
                'size_change': f'+{increase:.1f}%',
                'preview': preview + ('...' if len(encoded) > 200 else ''),
                'full_output': encoded.decode('ascii'),
                'charset': charset,
                'results': enc_results,
            }
        else:
            if encoding == 'base32':
                decoded = base64.b32decode(data.upper().strip())
            else:
                decoded = base64.b64decode(data)

            out_size = len(decoded)
            reduction = ((1 - out_size / file_size) * 100) if file_size else 0
            ftype = _detect_file_type(decoded)

            preview_text = decoded[:200].decode('utf-8', errors='replace') if ftype.startswith('Text') else f'[Binary data — {ftype}]'
            dec_results = [
                {'label': 'Standard',       'value': enc_label,                    'type': 'info'},
                {'label': 'Operation',      'value': 'Decode (Text → Binary)',     'type': 'info'},
                {'label': 'Input Size',     'value': f'{file_size:,} bytes',        'type': 'info'},
                {'label': 'Output Size',    'value': f'{out_size:,} bytes',         'type': 'info'},
                {'label': 'Size Change',    'value': f'-{reduction:.1f}%',          'type': 'success'},
                {'label': 'Detected Type',  'value': ftype,                         'type': 'info'},
                {'label': 'Output Preview', 'value': preview_text,                  'type': 'mono'},
            ]
            return {
                'status': 'success',
                'mode': 'decode',
                'encoding': enc_label,
                'filename': filename,
                'verdict': f'{enc_label} Decoding Complete',
                'verdict_type': 'success',
                'input_size': f'{file_size:,} bytes',
                'output_size': f'{out_size:,} bytes',
                'size_change': f'-{reduction:.1f}%',
                'detected_type': ftype,
                'preview': preview_text,
                'download_b64': base64.b64encode(decoded).decode('ascii'),
                'results': dec_results,
            }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


def _detect_file_type(data):
    sigs = [
        (b'\x89PNG', 'PNG Image'), (b'\xff\xd8\xff', 'JPEG Image'),
        (b'GIF8', 'GIF Image'), (b'BM', 'BMP Image'),
        (b'PK\x03\x04', 'ZIP Archive'), (b'%PDF', 'PDF Document'),
        (b'\x1f\x8b', 'GZIP Archive'), (b'Rar!', 'RAR Archive'),
        (b'ID3', 'MP3 Audio'), (b'RIFF', 'WAV/AVI File'),
        (b'\x4d\x5a', 'Windows Executable'), (b'\x7fELF', 'ELF Executable'),
    ]
    for sig, label in sigs:
        if data[:len(sig)] == sig:
            return label
    try:
        data[:200].decode('utf-8')
        return 'Text / UTF-8'
    except Exception:
        return 'Unknown Binary'


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: FILE SIGNATURE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

FILE_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': {'name': 'PNG Image', 'extensions': ['png']},
    b'\xff\xd8\xff': {'name': 'JPEG Image', 'extensions': ['jpg', 'jpeg']},
    b'GIF87a': {'name': 'GIF Image', 'extensions': ['gif']},
    b'GIF89a': {'name': 'GIF Image', 'extensions': ['gif']},
    b'BM': {'name': 'BMP Image', 'extensions': ['bmp']},
    b'%PDF': {'name': 'PDF Document', 'extensions': ['pdf']},
    b'PK\x03\x04': {'name': 'ZIP Archive', 'extensions': ['zip', 'docx', 'xlsx', 'pptx', 'jar']},
    b'PK\x05\x06': {'name': 'ZIP Archive (empty)', 'extensions': ['zip']},
    b'Rar!\x1a\x07': {'name': 'RAR Archive', 'extensions': ['rar']},
    b'\x1f\x8b': {'name': 'GZIP Archive', 'extensions': ['gz', 'tgz']},
    b'7z\xbc\xaf\x27\x1c': {'name': '7-Zip Archive', 'extensions': ['7z']},
    b'\x4d\x5a': {'name': 'Windows Executable', 'extensions': ['exe', 'dll', 'sys', 'com']},
    b'\x7fELF': {'name': 'ELF Executable', 'extensions': ['elf', 'so', 'out']},
    b'\xca\xfe\xba\xbe': {'name': 'Java Class File', 'extensions': ['class']},
    b'ID3': {'name': 'MP3 Audio (ID3)', 'extensions': ['mp3']},
    b'\xff\xfb': {'name': 'MP3 Audio', 'extensions': ['mp3']},
    b'RIFF': {'name': 'RIFF Container (WAV/AVI)', 'extensions': ['wav', 'avi']},
    b'ftyp': {'name': 'MP4/MOV Video', 'extensions': ['mp4', 'mov', 'm4v']},
    b'\x00\x00\x01\xba': {'name': 'MPEG Video', 'extensions': ['mpg', 'mpeg']},
    b'\x00\x00\x01\xb3': {'name': 'MPEG Video', 'extensions': ['mpg', 'mpeg']},
    b'OggS': {'name': 'OGG Container', 'extensions': ['ogg', 'ogv', 'oga']},
    b'fLaC': {'name': 'FLAC Audio', 'extensions': ['flac']},
    b'MSCF': {'name': 'Cabinet File', 'extensions': ['cab']},
    b'\xd0\xcf\x11\xe0': {'name': 'MS Office 97-2003', 'extensions': ['doc', 'xls', 'ppt']},
    b'SQLite': {'name': 'SQLite Database', 'extensions': ['db', 'sqlite', 'sqlite3']},
    b'\x25\x21': {'name': 'PostScript', 'extensions': ['ps', 'eps']},
    b'\x1a\x45\xdf\xa3': {'name': 'Matroska/WebM Video', 'extensions': ['mkv', 'webm']},
}


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: FILE SIGNATURE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/signature', methods=['POST'])
def api_signature():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file provided'}), 400
    path = _save(f)
    try:
        result = analyze_signature(path, f.filename)
        return jsonify(result)
    finally:
        _cleanup(path)


def analyze_signature(path, original_filename):
    filename = original_filename or os.path.basename(path)
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    size = os.path.getsize(path)

    with open(path, 'rb') as f:
        header = f.read(32)

    detected_type = None
    detected_exts = []

    for sig, info in FILE_SIGNATURES.items():
        offset = 4 if info['name'] == 'MP4/MOV Video' else 0
        check = header[offset:offset + len(sig)]
        if check == sig:
            detected_type = info['name']
            detected_exts = info['extensions']
            break

    if not detected_type:
        detected_type = _detect_magic(header) or 'Unknown / Unrecognized'
        detected_exts = []

    mismatch = ext and detected_exts and ext not in detected_exts
    entropy = _byte_entropy(header + open(path, 'rb').read(65536))

    results = [
        {'label': 'File Name',        'value': filename, 'type': 'info'},
        {'label': 'File Size',        'value': f'{size:,} bytes', 'type': 'info'},
        {'label': 'Extension',        'value': f'.{ext}' if ext else '(none)', 'type': 'info'},
        {'label': 'Magic Bytes',      'value': header[:8].hex().upper(), 'type': 'mono'},
        {'label': 'Detected Type',    'value': detected_type, 'type': 'info'},
        {'label': 'Expected Ext(s)',  'value': ', '.join(f'.{e}' for e in detected_exts) if detected_exts else 'N/A', 'type': 'info'},
        {'label': 'File Entropy',     'value': f'{entropy:.4f} bits/byte', 'type': 'info'},
    ]

    findings = []
    if mismatch:
        findings.append(f'Extension mismatch: .{ext} declared but file is actually {detected_type}')
        results.append({'label': '⚠ MISMATCH DETECTED', 'value': f'File claims to be .{ext} but magic bytes identify it as {detected_type}', 'type': 'warning'})
    else:
        results.append({'label': '✓ Signature Match', 'value': f'Extension matches detected type ({detected_type})', 'type': 'success'})

    if entropy > 7.5:
        findings.append(f'High entropy ({entropy:.4f}) — file may be encrypted, compressed, or packed')
        results.append({'label': '⚠ High Entropy', 'value': 'Possible encrypted/packed content — common anti-forensics technique', 'type': 'warning'})

    verdict = 'MISMATCH DETECTED — Potential anti-forensics / file masquerading' if mismatch else 'SIGNATURE MATCH — File extension consistent with content'
    vtype = 'warning' if mismatch else 'success'

    return {
        'status': 'success',
        'filename': filename,
        'findings': findings,
        'verdict': verdict,
        'verdict_type': vtype,
        'results': results
    }


def _detect_magic(header):
    for sig, info in FILE_SIGNATURES.items():
        if header[:len(sig)] == sig:
            return info['name']
    return None


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: DEEPFAKE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/deepfake', methods=['POST'])
def api_deepfake():
    f = request.files.get('file')
    media_type = request.form.get('type', 'image')
    if not f:
        return jsonify({'error': 'No file provided'}), 400
    path = _save(f)
    if media_type == 'image':
        result = deepfake_image(path)
    elif media_type == 'video':
        result = deepfake_video(path)
    else:
        return jsonify({'error': 'Audio deepfake detection is not supported'}), 400
    _cleanup(path)
    return jsonify(result)


def deepfake_image(path):
    import os
    import cv2
    import numpy as np
    from PIL import Image

    filename = os.path.basename(path)
    size = os.path.getsize(path)

    results = []
    results.append({'label': 'File', 'value': filename, 'type': 'info'})
    results.append({'label': 'Size', 'value': f'{size/1024:.2f} KB', 'type': 'info'})

    # ================================
    # LOAD IMAGE
    # ================================
    try:
        img = Image.open(path).convert("RGB")
    except:
        return {
            "status": "error",
            "message": "Cannot open image"
        }

    pipe = get_model()

    try:
        res = pipe(img)
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

    fake = 0.0
    real = 0.0

    # ================================
    # EXTRACT MODEL SCORES
    # ================================
    for item in res:
        label = str(item["label"]).lower()
        score = float(item["score"])

        if "fake" in label:
            fake = score
        elif "real" in label or "auth" in label:
            real = score

    # fallback
    if fake == 0 and real == 0 and len(res) >= 2:
        fake = float(res[0]["score"])
        real = float(res[1]["score"])

    # ================================
    # MODEL ANALYSIS SECTION
    # ================================
    results.append({
    "label": "Model Analysis",
    "value": "",
    "type": "section"
})

    model_indicators = []

    if fake >= 0.65:
        model_indicators.append("High probability from AI model (>65%)")
    elif fake >= 0.40:
        model_indicators.append("Moderate probability from AI model (40–65%)")
    else:
        model_indicators.append("Low fake probability (<40%)")

    if fake > real:
        model_indicators.append("Model confidence favors FAKE over REAL")
    else:
        model_indicators.append("Model confidence favors REAL over FAKE")

    for item in res:
        model_indicators.append(f"{item['label']} confidence: {round(item['score']*100,2)}%")

    for ind in model_indicators:
        results.append({
            "label": "Model Finding",
            "value": ind,
            "type": "warning" if fake >= 0.40 else "info"
        })

    # ================================
    # FORENSIC ANALYSIS SECTION
    # ================================
    results.append({
    "label": "Forensic Artifact Analysis",
    "value": "",
    "type": "section"
})

    forensic_indicators = []

    try:
        img_cv = cv2.imread(path, cv2.IMREAD_GRAYSCALE)

        # Blur detection
        blur = cv2.Laplacian(img_cv, cv2.CV_64F).var()
        if blur < 25:
            forensic_indicators.append(f"Low sharpness (blur={blur:.2f}) — GAN smoothing artifact")
        else:
            forensic_indicators.append(f"Normal sharpness (blur={blur:.2f})")

        # Noise estimation
        noise = np.std(img_cv)
        if noise < 12:
            forensic_indicators.append(f"Low noise level ({noise:.2f}) — synthetic texture suspected")
        else:
            forensic_indicators.append(f"Normal noise level ({noise:.2f})")

        # Edge density
        edges = cv2.Canny(img_cv, 100, 200)
        edge_ratio = edges.mean() / 255
        if edge_ratio < 0.02:
            forensic_indicators.append(f"Weak edge density ({edge_ratio:.4f}) — blending artifact")
        else:
            forensic_indicators.append(f"Normal edge density ({edge_ratio:.4f})")

        # Frequency analysis
        f = np.fft.fft2(img_cv)
        fshift = np.fft.fftshift(f)
        magnitude = np.log(np.abs(fshift) + 1)
        freq_score = np.mean(magnitude)

        if freq_score < 4.5:
            forensic_indicators.append(f"Low frequency complexity ({freq_score:.2f}) — GAN pattern suspected")
        else:
            forensic_indicators.append(f"Normal frequency distribution ({freq_score:.2f})")

    except:
        forensic_indicators.append("Image forensic analysis skipped")

    for ind in forensic_indicators:
        results.append({
            "label": "Artifact Finding",
            "value": ind,
            "type": "warning" if "low" in ind.lower() or "weak" in ind.lower() else "info"
        })

    # ================================
    # FINAL VERDICT
    # ================================
    if fake >= 0.65:
        verdict = "LIKELY DEEPFAKE"
        vtype = "danger"
    elif fake >= 0.40:
        verdict = "SUSPICIOUS"
        vtype = "warning"
    else:
        verdict = "AUTHENTIC"
        vtype = "success"

    results.append({
        "label": "FORENSIC VERDICT",
        "value": "Based on AI model confidence + artifact analysis (blur, noise, edges, frequency)",
        "type": vtype
    })

    return {
        "status": "success",
        "filename": filename,
        "score": round(fake * 100, 1),
        "verdict": verdict,
        "verdict_type": vtype,
        "confidence": f"{round(fake*100,1)} / 100",
        "results": results
    }
    
def deepfake_video(path):
    import os
    import cv2
    import numpy as np
    from PIL import Image
    import io
    import base64

    filename = os.path.basename(path)
    size = os.path.getsize(path)

    results = []
    results.append({'label': 'File', 'value': filename, 'type': 'info'})
    results.append({'label': 'Size', 'value': f'{size/1024/1024:.2f} MB', 'type': 'info'})

    cap = cv2.VideoCapture(path)

    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    duration = total / fps if total > 0 else 0

    # ================================
    # FRAME SAMPLING
    # ================================
    if duration <= 5:
        sample_count = min(20, total)
    elif duration <= 15:
        sample_count = min(25, total)
    elif duration <= 30:
        sample_count = min(35, total)
    else:
        sample_count = min(45, total)

    indexes = np.linspace(0, total - 1, sample_count).astype(int)

    face_detector = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )

    pipe = get_model()

    fake_scores = []
    frame_scores = []
    frames = []

    # ================================
    # PROCESS FRAMES
    # ================================
    for i, idx in enumerate(indexes):

        cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
        ret, frame = cap.read()

        if not ret:
            continue

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        faces = face_detector.detectMultiScale(gray, 1.1, 5, minSize=(60, 60))

        if len(faces) > 0:
            faces = sorted(faces, key=lambda x: x[2]*x[3], reverse=True)
            x, y, w, h = faces[0]
            crop = rgb[y:y+h, x:x+w]
        else:
            crop = rgb

        img = Image.fromarray(crop)

        try:
            res = pipe(img)
        except:
            continue

        fake = 0.0
        real = 0.0

        for item in res:
            label = str(item["label"]).lower()
            score = float(item["score"])

            if "fake" in label:
                fake = score
            elif "real" in label or "auth" in label:
                real = score

        if fake == 0 and real == 0 and len(res) >= 2:
            fake = float(res[0]["score"])
            real = float(res[1]["score"])

        if len(faces) > 0:
            fake = min(1.0, fake + 0.04)

        fake_scores.append(fake)
        frame_scores.append(fake)

        frames.append({
            "frame": int(idx),
            "timestamp": round(idx / fps, 2),
            "fake_score": round(fake, 3)
        })

    cap.release()

    if not fake_scores:
        return {"status": "error", "message": "No frames processed"}

    # ================================
    # AGGREGATION
    # ================================
    avg_fake = float(np.mean(fake_scores))
    med_fake = float(np.median(fake_scores))
    fake_ratio = sum(x >= 0.45 for x in fake_scores) / len(fake_scores)
    variance = max(frame_scores) - min(frame_scores)

    # ================================
    # MODEL ANALYSIS
    # ================================
    results.append({
        "label": "Model Analysis",
        "value": "",
        "type": "section"
    })

    indicators = []

    if avg_fake >= 0.65:
        indicators.append("High average fake probability across frames (>65%)")
    elif avg_fake >= 0.40:
        indicators.append("Moderate fake probability across frames (40–65%)")
    else:
        indicators.append("Low fake probability across frames (<40%)")

    if fake_ratio > 0.6:
        indicators.append("Majority of frames classified as FAKE")
    elif fake_ratio > 0.3:
        indicators.append("Some frames show FAKE characteristics")

    for ind in indicators:
        results.append({
            "label": "Model Finding",
            "value": ind,
            "type": "warning" if avg_fake >= 0.40 else "info"
        })

    # ================================
    # FORENSIC ANALYSIS
    # ================================
    results.append({
        "label": "Forensic Artifact Analysis",
        "value": "",
        "type": "section"
    })

    forensic = []

    if variance > 0.4:
        forensic.append("High inconsistency between frames — possible manipulation")
    else:
        forensic.append("Frames are consistent in classification")

    forensic.append(f"Fake frame ratio: {round(fake_ratio*100,2)}%")
    forensic.append(f"Frame score variance: {round(variance,3)}")

    for ind in forensic:
        results.append({
            "label": "Artifact Finding",
            "value": ind,
            "type": "warning" if "inconsistency" in ind.lower() else "info"
        })

    # ================================
    # FINAL VERDICT
    # ================================
    if med_fake >= 0.62 or fake_ratio >= 0.65:
        final_verdict = "LIKELY DEEPFAKE"
        final_type = "danger"
    elif med_fake >= 0.40 or fake_ratio >= 0.35:
        final_verdict = "SUSPICIOUS"
        final_type = "warning"
    else:
        final_verdict = "AUTHENTIC"
        final_type = "success"

    results.append({
        "label": "FORENSIC VERDICT",
        "value": "Based on multi-frame AI analysis + temporal consistency",
        "type": final_type
    })

    return {
        "status": "success",
        "filename": filename,
        "score": round(avg_fake * 100, 1),
        "verdict": final_verdict,
        "verdict_type": final_type,
        "confidence": f"{round(avg_fake*100,1)} / 100",
        "video_info": {
            "frames_analyzed": len(fake_scores),
            "duration_sec": round(duration, 2)
        },
        "results": results,
        "frames": frames
    }



# ─────────────────────────────────────────────────────────────────────────────
# SHARED UTILS
# ─────────────────────────────────────────────────────────────────────────────

def _byte_entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return sum(-p/n * math.log2(p/n) for p in freq if p > 0)

def _get_verdict(score):
    if score >= 75:
        return ('LIKELY DEEPFAKE / AI-GENERATED', 'danger',
                f'High ({score:.0f}/100) — Multiple forensic indicators suggest synthetic origin')
    elif score >= 55:
        return ('SUSPICIOUS — POSSIBLE MANIPULATION', 'warning',
                f'Moderate-High ({score:.0f}/100) — Anomalies detected; further investigation recommended')
    elif score >= 35:
        return ('INCONCLUSIVE — MINOR ANOMALIES', 'info',
                f'Moderate ({score:.0f}/100) — Minor irregularities; likely authentic')
    else:
        return ('LIKELY AUTHENTIC / REAL', 'success',
                f'Low ({score:.0f}/100) — No significant deepfake indicators detected')


if __name__ == '__main__':
    print('\n' + '='*60)
    print('  Advanced Digital Forensics & Anti-Forensics Toolkit')
    print('  Running at: http://localhost:5050')
    print('='*60 + '\n')
    app.run(host='0.0.0.0', port=5050, debug=False)
