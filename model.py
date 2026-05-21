# model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import pickle
from data import generate_dummy_data

# 1. Generate data
df = generate_dummy_data(500)
X = df[["failed_attempts_last_5min", "success_last_hour", "distinct_usernames_per_ip", "time_between_attempts"]]
y = df["is_attack"]

# 2. Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train logistic regression
model = LogisticRegression()
model.fit(X_train, y_train)

# 4. Save the model
with open("attack_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved!")
