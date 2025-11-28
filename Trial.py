import pickle

# Load both
with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

with open("modele.pkl", "rb") as f:
    model = pickle.load(f)

# Predict new URL
url = ["http://login-verification-update.com"]
X = vectorizer.transform(url)
prediction = model.predict(X)

label = "Phishing" if prediction[0] == 1 else "Safe"
print(f"🔎 {url[0]} → {label}")
