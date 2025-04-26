import numpy as np
from sklearn.ensemble import RandomForestClassifier

class QuantumClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.training_data = [
            [100, 1, 6, 0, 0], [200, 2, 6, 0, 0], [500, 10, 6, 1, 1],
            [50, 5, 17, 0, 1], [300, 3, 6, 0, 0], [1000, 20, 6, 1, 1]
        ]
        self.labels = [0, 0, 1, 1, 0, 1]
        self.model.fit(self.training_data, self.labels)
        self.threshold = 0.5  # Initial threshold for probability

    def predict(self, features):
        prob = self.model.predict_proba([features])[0][1]  # Probability of being unsafe
        return 1 if prob > self.threshold else 0

    def adjust_threshold(self, recent_predictions):
        # Adaptive thresholding: increase if too many false positives, decrease if missing attacks
        unsafe_ratio = sum(recent_predictions) / len(recent_predictions) if recent_predictions else 0
        if unsafe_ratio > 0.7:  # Too many unsafe detections
            self.threshold += 0.05
        elif unsafe_ratio < 0.3:  # Too few unsafe detections
            self.threshold -= 0.05
        self.threshold = max(0.1, min(0.9, self.threshold))  # Keep within bounds

quantum_clf = QuantumClassifier()