import streamlit as st
import pickle, json, re, requests
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Load model
with open("models/content_model_rt.pkl", "rb") as f:
    model = pickle.load(f)
with open("models/feature_names_rt.json", "r") as f:
    FEATURE_NAMES = json.load(f)

# Feature extractor (real-time only)
def extract_features(url):
    features = {}
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    features["NumDots"] = url.count('.')
    features["NumDash"] = url.count('-')
    features["UrlLength"] = len(url)
    features["AtSymbol"] = 1 if "@" in url else 0
    features["NumUnderscore"] = url.count('_')
    features["NumPercent"] = url.count('%')
    features["NumQueryComponents"] = url.count('=')
    features["NumAmpersand"] = url.count('&')
    features["NumHash"] = url.count('#')
    features["NumNumericChars"] = sum(c.isdigit() for c in url)
    features["NoHttps"] = 0 if url.lower().startswith("https") else 1
    features["IpAddress"] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    features["HostnameLength"] = len(hostname)
    features["PathLength"] = len(path)
    features["QueryLength"] = len(query)
    features["DoubleSlashInPath"] = 1 if '//' in path else 0

    # HTML features
    features["IframeOrFrame"] = 0
    features["PopUpWindow"] = 0
    features["RightClickDisabled"] = 0
    features["ExtFormAction"] = 0

    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent":"Mozilla/5.0"})
        html = resp.text
        soup = BeautifulSoup(html, "lxml")
        features["IframeOrFrame"] = 1 if soup.find("iframe") else 0
        features["PopUpWindow"] = 1 if re.search(r"window\.open", html) else 0
        features["RightClickDisabled"] = 1 if re.search(r"event.button ?== ?2", html) else 0
        form = soup.find("form")
        if form and form.get("action"):
            if urlparse(form.get("action")).netloc not in [hostname, ""]:
                features["ExtFormAction"] = 1
    except:
        pass

    return pd.DataFrame([features]).reindex(columns=FEATURE_NAMES, fill_value=0)

# Streamlit UI
st.set_page_config(page_title="Phishing Detector RT", page_icon="🔒", layout="centered")
st.title("🔒 Phishing Website Detector — Real-Time")
url = st.text_input("🌐 Website URL")
debug_mode = st.sidebar.checkbox("🛠️ Debug Mode")

if st.button("🚀 Check Website") and url:
    input_df = extract_features(url)
    pred = model.predict(input_df)[0]
    proba = model.predict_proba(input_df)[0]
    if pred == 1:
        st.error("⚠️ Phishing Website Detected!")
    else:
        st.success("✅ Legitimate Website")
    st.write(f"Confidence — Legitimate: {proba[0]*100:.2f}%, Phishing: {proba[1]*100:.2f}%")
    if debug_mode:
        st.write("### 🛠️ Extracted Features")
        st.dataframe(input_df.T.rename(columns={0:"Value"}))
