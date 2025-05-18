import pandas as pd
import numpy as np
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder
import tensorflow as tf

class AIModel:
    def __init__(self):
        self.svm = SVC()
        self.ann = self._build_ann()
        self.label_encoder = LabelEncoder()
        self.word_index = {}

    def _build_ann(self):
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(2,)),
            tf.keras.layers.Dense(8, activation='relu'),
            tf.keras.layers.Dense(1, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def train(self, data_path):
        df = pd.read_excel(data_path, engine='openpyxl')
        df.columns = df.columns.str.strip()

        required_columns = ['ZAP Alert Name', 'Description', 'CWE', 'Risk']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Missing required column: {col}")

        texts = (df['ZAP Alert Name'].astype(str) + " " + df['Description'].astype(str))
        self.word_index = {word: idx for idx, word in enumerate(set(" ".join(texts).split()))}

        X_svm = np.array([
            np.mean([self.word_index.get(word, 0) for word in text.split()] or [0])
            for text in texts
        ]).reshape(-1, 1)

        df['CWE'] = df['CWE'].astype(str)
        self.label_encoder.fit(df['CWE'])
        y_svm = self.label_encoder.transform(df['CWE'])

        self.svm.fit(X_svm, y_svm)

        df['CWE_encoded'] = self.label_encoder.transform(df['CWE'])
        df['Risk'] = pd.to_numeric(df['Risk'], errors='coerce')
        df = df.dropna(subset=['CWE_encoded', 'Risk'])

        X_ann = df[['CWE_encoded', 'Risk']].values
        y_ann = df['Risk'].values

        self.ann.fit(X_ann, y_ann, epochs=10, verbose=0)

    def predict(self, alert_name, description, risk_label="Medium"):
        if not self.word_index:
            raise RuntimeError("Model must be trained before prediction.")

        text = alert_name + " " + description
        words = [self.word_index.get(word, 0) for word in text.split()]
        mean_val = np.mean(words)
        cwe_idx = self.svm.predict(np.array([[mean_val]]))[0]
        cwe = self.label_encoder.inverse_transform([cwe_idx])[0]

        risk_map = {'Informational': 1, 'Low': 3, 'Medium': 5, 'High': 8}
        risk_val = risk_map.get(risk_label, 5)

        severity = self.ann.predict(np.array([[cwe_idx, risk_val]]))[0][0]

        return {
            'name': alert_name,
            'description': description,
            'severity': round(severity, 2),
            'cwe': cwe,
            'solution': f"Refer to CWE-{cwe} mitigation strategies."
        }
