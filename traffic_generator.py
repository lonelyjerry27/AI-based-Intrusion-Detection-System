import tensorflow as tf
from tensorflow.keras import layers
import numpy as np
import random
from datetime import datetime

def build_generator():
    model = tf.keras.Sequential([
        layers.Dense(16, activation="relu", input_dim=5),
        layers.Dense(5, activation="sigmoid")
    ])
    return model

generator = build_generator()
generator.compile(optimizer="adam", loss="mse")

def generate_synthetic_traffic():
    noise = tf.random.normal([1, 5])
    synthetic = generator(noise).numpy()[0] * [1500, 25, 17, 1, 1]
    return {
        "packet_size": int(synthetic[0]),
        "frequency": int(synthetic[1]),
        "protocol": int(synthetic[2]),
        "flags": int(synthetic[3]),
        "anomaly": int(synthetic[4]),
        "source_ip": ".".join(str(random.randint(0, 255)) for _ in range(4)),
        "mac_address": ":".join(["{:02x}".format(random.randint(0, 255)) for _ in range(6)]),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }