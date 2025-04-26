import json
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense

class TimeSeriesPredictor:
    def __init__(self):
        self.model = Sequential([
            LSTM(50, activation="relu", input_shape=(5, 2), return_sequences=False),
            Dense(1)
        ])
        self.model.compile(optimizer="adam", loss="mse")

    def predict_next(self, filename="traffic_data.json"):
        try:
            with open(filename, "r") as f:
                history = json.load(f)
            if len(history) < 5:
                return 0
            recent = [[t["packet_size"], t["frequency"]] for t in history[-5:]]
            X = np.array([recent])
            prediction = self.model.predict(X, verbose=0)[0][0]
            return 1 if prediction > 0.5 else 0
        except:
            return 0

predictor = TimeSeriesPredictor()