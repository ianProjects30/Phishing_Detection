from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_dance.contrib.google import make_google_blueprint, google
import sqlite3
import bcrypt
import hashlib
import os
import numpy as np
import pickle
import warnings
import requests
from dotenv import load_dotenv
from feature import FeatureExtraction
from gsb_utils import check_gsb 

# ---------------- LOAD ENV ----------------
load_dotenv()  # Loads variables from .env

# Suppress warnings
warnings.filterwarnings('ignore')

# ---------------- FLASK SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_secret_key')

# ---------------- GOOGLE LOGIN (OAuth) ----------------
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_url="/google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# ---------------- DATABASE SETUP ----------------
DB_FILE = 'users.db'
SECRET_PEPPER = os.environ.get('SECRET_PEPPER', 'dev_pepper')

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password BLOB NOT NULL,
            salt_for_secret BLOB NOT NULL,
            hashed_secret2 BLOB NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            url TEXT NOT NULL,
            confidence REAL NOT NULL,
            is_safe INTEGER NOT NULL,
            source TEXT DEFAULT 'ML',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ---------------- HELPER FUNCTIONS ----------------
def generate_random_salt():
    return os.urandom(16)

def hash_secret_with_salt(secret, salt):
    return hashlib.sha256(secret.encode('utf-8') + salt).hexdigest()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (email.lower(),))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email, password):
    salt_for_secret = generate_random_salt()
    hashed_secret = hash_secret_with_salt(SECRET_PEPPER, salt_for_secret)
    hashed_secret2 = bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt())
    combined_password = password + hashed_secret2.decode('utf-8')
    final_hashed_password = bcrypt.hashpw(combined_password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, hashed_password, salt_for_secret, hashed_secret2) VALUES (?, ?, ?, ?)',
            (email.lower(), final_hashed_password, salt_for_secret, hashed_secret2)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def validate_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return False
    stored_hashed_password, salt, hashed_secret2 = user[1], user[2], user[3]
    combined_input = password + hashed_secret2.decode('utf-8')
    return bcrypt.checkpw(combined_input.encode('utf-8'), stored_hashed_password)

# ---------------- LOAD ML MODELS ----------------
try:
    with open("pickle/modele.pkl", "rb") as f_model, \
         open("pickle/vectorizer.pkl", "rb") as f_vect:
        email_clf = pickle.load(f_model)
        email_vect = pickle.load(f_vect)
    with open("pickle/model.pkl", "rb") as f_url_model:
        url_clf = pickle.load(f_url_model)
except FileNotFoundError:
    print("⚠️ WARNING: Missing pickle model files.")
    email_clf, email_vect, url_clf = None, None, None

# ---------------- GEMINI CONFIG ----------------
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"

def analyze_with_gemini(prompt_text):
    try:
        payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
        response = requests.post(GEMINI_ENDPOINT, headers={"Content-Type": "application/json"}, json=payload)
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        print(f"Gemini API error: {e}")
        return "AI analysis unavailable at this time."

# ---------------- REACHABILITY CHECK ----------------
def check_url_status(url, timeout=6):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return {"reachable": True, "status_code": response.status_code, "final_url": response.url}
    except requests.exceptions.Timeout:
        return {"reachable": False, "detail": "Connection timed out"}
    except requests.exceptions.SSLError:
        return {"reachable": False, "detail": "SSL error"}
    except requests.exceptions.ConnectionError as e:
        return {"reachable": False, "detail": f"Connection error: {str(e)}"}
    except Exception as e:
        return {"reachable": False, "detail": str(e)}

# ---------------- FEATURE REASONING ----------------
def generate_reason(features):
    phishing_reasons, safe_reasons = [], []
    if len(features) < 30:
        return {"summary": "Feature extraction failed.", "reasons": ["Not enough data extracted."]}
    if features[0] == 1: phishing_reasons.append("Uses an IP address instead of a domain.")
    if features[1] == 1: phishing_reasons.append("URL length is suspiciously long.")
    if features[5] == 1: phishing_reasons.append("Contains '@' symbol which can mislead users.")
    if features[7] == 1: phishing_reasons.append("Contains multiple redirections using '//'.")
    if features[13] == 1: phishing_reasons.append("Does not use HTTPS (unsafe connection).")
    if phishing_reasons:
        return {"summary": "Suspicious signs detected:", "reasons": phishing_reasons}
    else:
        return {"summary": "URL appears safe.", "reasons": ["No suspicious patterns found."]}

# ---------------- ROUTES ----------------
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        return redirect(url_for('auth'))

    xx, url, ai_report = -1, None, None
    reason_info = {'summary': None, 'reasons': []}
    source = "ML"
    y_pred = -1

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            status = check_url_status(url)
            if not status["reachable"]:
                xx = 0.0
                y_pred = -1
                source = "Network"
                reason_info = {"summary": "⚠️ Site unreachable.", "reasons": [f"Detail: {status.get('detail', 'Unknown error')}"]}
                ai_report = f"This site could not be analyzed because it’s unreachable ({status.get('detail', 'unknown reason')})."
            else:
                gsb_result = check_gsb(url)
                if gsb_result['label'] == 'phishing':
                    xx = 1.0
                    y_pred = 0
                    source = "GSB"
                    reason_info = {"summary": "⚠️ Reported as phishing by Google Safe Browsing.", "reasons": [f"Threat type(s): {gsb_result.get('detail', 'unspecified')}"]}
                    ai_report = "This URL is phishing because it has been reported as unsafe in Google Safe Browsing."
                else:
                    if url_clf is None:
                        flash("⚠️ URL ML model not loaded.", "danger")
                        ai_report = "Unable to analyze because the ML model is not available."
                    else:
                        try:
                            obj = FeatureExtraction(url)
                            features = obj.getFeaturesList()
                            X = np.array(features).reshape(1, -1)
                            y_pred = url_clf.predict(X)[0]
                            pro_safe = url_clf.predict_proba(X)[0, 1]
                            xx = round(pro_safe, 2)
                            reason_info = generate_reason(features)

                            prompt = f"Analyze this URL for phishing: {url}. Respond with EXACTLY ONE sentence starting with either 'This URL is safe because...' or 'This URL is phishing because...'."
                            ai_report = analyze_with_gemini(prompt)

                            if ai_report and any(word in ai_report.lower() for word in ["phishing", "malicious", "dangerous", "unsafe"]):
                                y_pred = 0
                                xx = 0.0
                                source = "AI Override"
                                reason_info = {"summary": "⚠️ Overridden by AI Analysis.", "reasons": ["Gemini AI flagged this site as potentially malicious."]}
                        except Exception as e:
                            flash(f"ML Error: {e}", "danger")
                            y_pred = -1
                            xx = 0.0
                            ai_report = f"Analysis failed due to error: {e}"
                            print(f"Prediction failed for {url}: {e}")

            try:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO url_history (username, url, confidence, is_safe, source) VALUES (?, ?, ?, ?, ?)',
                    (session['user'], url, float(xx), int(y_pred) if y_pred != -1 else None, source)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"DB insert failed: {e}")

    return render_template('index.html', user=session.get('user'), xx=xx, url=url,
                           ai_report=ai_report, reason_summary=reason_info['summary'],
                           reason_list=reason_info['reasons'], y_pred=y_pred)

@app.route('/predict', methods=['POST'])
def predict_email():
    data = request.get_json(force=True, silent=True) or {}
    email_text = data.get('email', '').strip() or request.form.get('email', '').strip()
    if not email_text:
        return jsonify({'error': 'No email content provided.'}), 400
    if email_clf is None or email_vect is None:
        prediction, confidence = 'Model Error', 0.0
    else:
        try:
            X = email_vect.transform([email_text])
            proba = email_clf.predict_proba(X)[0]
            y_pred = email_clf.predict(X)[0]
            confidence = float(proba.max())
            is_phish = (int(y_pred) == 1)
            prediction = 'Phishing Email' if is_phish else 'Safe Email'
        except Exception as e:
            prediction, confidence = 'ML Error', 0.0
            print(f"Email ML Error: {e}")
    ai_analysis = analyze_with_gemini(f"Analyze this email for phishing: {email_text}. Respond with exactly one sentence.")
    return jsonify({'prediction': prediction, 'confidence': confidence, 'ai_analysis': ai_analysis})

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if 'user' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        mode = request.form['form_mode']
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if mode == 'signup':
            confirm = request.form.get('confirmPassword')
            if password != confirm:
                flash("Passwords do not match.", "danger")
            elif create_user(email, password):
                flash("Account created! Please log in.", "success")
            else:
                flash("Email already exists.", "warning")
        else:
            if validate_login(email, password):
                session['user'] = email
                flash(f"Welcome back, {email}!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "danger")
    return render_template('login.html')

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('auth'))
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT url, confidence, is_safe, source, timestamp FROM url_history WHERE username = ? ORDER BY timestamp DESC', (session['user'],))
    rows = cursor.fetchall()
    conn.close()
    return render_template('history.html', user=session['user'], history=rows)

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out.", "info")
    return redirect(url_for('auth'))

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Google login failed.", "danger")
        return redirect(url_for('auth'))
    user_info = resp.json()
    email = user_info.get("email").lower()
    if not get_user_by_email(email):
        dummy_pass = bcrypt.gensalt().decode('utf-8')
        create_user(email, dummy_pass)
    session['user'] = email
    flash(f"Logged in as {email} via Google.", "success")
    return redirect(url_for('home'))

@app.route('/phishmail')
def phishmail():
    if 'user' not in session:
        return redirect(url_for('auth'))
    return render_template('phishmail.html', user=session['user'])

# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(debug=True)
