from flask import Flask, render_template, request, jsonify
import re
import urllib.parse

app = Flask(__name__)

# --- Rule-Based AI Logic ---

# 1. Scam Message Detector
SCAM_KEYWORDS = [
    'urgent', 'immediate action', 'winner', 'lottery', 'free money',
    'bank account suspended', 'verify your account', 'password reset',
    'gift card', 'click the link', 'claim your prize', 'western union',
    'cryptocurrency', 'bitcoin', 'investment opportunity'
]
URGENCY_KEYWORDS = ['act now', 'immediately', 'expires', 'final warning', 'urgent']

def analyze_message(text):
    text_lower = text.lower()
    score = 0
    detected_patterns = []
    
    # Check for keywords
    keyword_count = sum(1 for kw in SCAM_KEYWORDS if kw in text_lower)
    if keyword_count > 0:
        score += keyword_count * 15
        detected_patterns.append(f"Found {keyword_count} suspicious keywords.")
        
    # Check for urgency
    urgency_count = sum(1 for u in URGENCY_KEYWORDS if u in text_lower)
    if urgency_count > 0:
        score += urgency_count * 20
        detected_patterns.append("Detected high urgency/threat language.")
        
    # Check for excessive capitalization
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.3:
        score += 15
        detected_patterns.append("Excessive use of capital letters.")
        
    # Check for links
    urls = re.findall(r'(https?://[^\s]+)', text)
    if urls:
        score += 20
        detected_patterns.append(f"Contains {len(urls)} link(s). Be careful clicking unknown links.")

    # Cap score at 100
    probability = min(score, 100)
    
    if probability < 30:
        risk_level = "Safe"
        explanation = "The message does not exhibit common scam patterns."
    elif probability < 70:
        risk_level = "Suspicious"
        explanation = "The message contains some unusual patterns. Proceed with caution."
    else:
        risk_level = "Dangerous"
        explanation = "High probability of being a scam. Do not click any links or share personal info."

    if not detected_patterns:
        detected_patterns = ["No obvious threats detected."]

    return {
        "probability": probability,
        "risk_level": risk_level,
        "explanation": explanation,
        "patterns": detected_patterns
    }

# 2. Fake Job Posting Detector
JOB_SCAM_KEYWORDS = [
    'no experience required', 'work from home', 'quick cash',
    'wire transfer', 'payment upfront', 'cash checking', 
    'start immediately', 'guaranteed income', 'envelope stuffing'
]

def analyze_job(company, title, salary, email, description):
    score = 0
    detected_patterns = []
    desc_lower = description.lower()
    
    # Analyze Salary (Unrealistic detection)
    try:
        # Strip non-numeric except dot
        clean_salary = re.sub(r'[^\d.]', '', salary)
        if clean_salary:
            salary_val = float(clean_salary)
            # Basic heuristic: if it mentions per week and is very high, or just very high for generic
            if salary_val > 10000 and ('week' in desc_lower or 'day' in desc_lower):
                score += 30
                detected_patterns.append("Unrealistically high salary for the timeframe.")
    except ValueError:
        pass
        
    # Analyze Email
    if email:
        free_email_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        domain = email.split('@')[-1] if '@' in email else ''
        if domain.lower() in free_email_providers:
            score += 25
            detected_patterns.append("Uses a free email provider instead of a corporate domain.")
            
    # Analyze Description
    keyword_count = sum(1 for kw in JOB_SCAM_KEYWORDS if kw in desc_lower)
    if keyword_count > 0:
        score += keyword_count * 20
        detected_patterns.append(f"Found {keyword_count} suspicious phrases often used in fake jobs.")
        
    # Vague description
    if len(description.split()) < 20:
        score += 15
        detected_patterns.append("Job description is unusually short and vague.")

    probability = min(score, 100)
    
    if probability < 30:
        risk_level = "Safe"
        explanation = "Looks like a legitimate job posting."
    elif probability < 70:
        risk_level = "Suspicious"
        explanation = "Some red flags found. Verify the company independently."
    else:
        risk_level = "Dangerous"
        explanation = "Highly likely to be a fake job or employment scam."

    if not detected_patterns:
        detected_patterns = ["Information appears standard."]

    return {
        "probability": probability,
        "risk_level": risk_level,
        "explanation": explanation,
        "patterns": detected_patterns
    }

# 3. Phishing Link Detector
SUSPICIOUS_DOMAINS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
IMPERSONATED_BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'bank', 'netflix']

def analyze_link(url):
    score = 0
    detected_patterns = []
    
    # Ensure URL is parsable
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
    except Exception:
        return {"probability": 100, "risk_level": "Dangerous", "explanation": "Invalid URL format.", "patterns": ["Unparseable URL"]}

    # Check length
    if len(url) > 75:
        score += 10
        detected_patterns.append("URL is unusually long (often hides malicious paths).")

    # Check for IP address instead of domain
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
        score += 40
        detected_patterns.append("Uses an IP address instead of a domain name.")

    # Check for excessive subdomains
    subdomains = domain.split('.')
    if len(subdomains) > 3 and not ('co.uk' in domain or 'com.au' in domain):
        score += 20
        detected_patterns.append("Too many subdomains (common in phishing).")
        
    # Check TLD
    tld = subdomains[-1] if subdomains else ''
    if tld in SUSPICIOUS_DOMAINS:
        score += 30
        detected_patterns.append(f"Uses a suspicious top-level domain (.{tld}).")
        
    # Check for brand impersonation
    brand_found = False
    for brand in IMPERSONATED_BRANDS:
        if brand in domain and f"{brand}.com" not in domain:
            score += 40
            brand_found = True
            detected_patterns.append(f"Attempts to impersonate {brand.capitalize()}.")
            
    # Check for symbols in domain
    if '-' in domain and brand_found:
        score += 10
        detected_patterns.append("Uses hyphens with a brand name (e.g., paypal-secure.com).")
    if '@' in url:
        score += 30
        detected_patterns.append("Contains an '@' symbol (can be used to obscure the real destination).")

    # Path keywords
    if 'login' in path or 'secure' in path or 'account' in path:
        score += 15
        detected_patterns.append("Path targets sensitive actions (login, secure).")

    probability = min(score, 100)
    
    if probability < 30:
        risk_level = "Safe"
        explanation = "The link structure appears normal."
    elif probability < 70:
        risk_level = "Suspicious"
        explanation = "The link has suspicious characteristics. Verify the source."
    else:
        risk_level = "Dangerous"
        explanation = "High risk of phishing or malware. Do not visit this site."

    if not detected_patterns:
        detected_patterns = ["No obvious phishing patterns detected."]

    return {
        "probability": probability,
        "risk_level": risk_level,
        "explanation": explanation,
        "patterns": detected_patterns
    }


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze_message', methods=['POST'])
def api_analyze_message():
    data = request.json
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "No text provided"}), 400
    result = analyze_message(text)
    return jsonify(result)

@app.route('/api/analyze_job', methods=['POST'])
def api_analyze_job():
    data = request.json
    company = data.get('company', '')
    title = data.get('title', '')
    salary = data.get('salary', '')
    email = data.get('email', '')
    description = data.get('description', '')
    
    if not description:
        return jsonify({"error": "Job description is required"}), 400
        
    result = analyze_job(company, title, salary, email, description)
    return jsonify(result)

@app.route('/api/analyze_link', methods=['POST'])
def api_analyze_link():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = analyze_link(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
