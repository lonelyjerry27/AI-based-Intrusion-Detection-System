import random

class RLAgent:
    def __init__(self):
        self.correct_predictions = 0
        self.total_predictions = 0

    def update(self, prediction, true_label):
        reward = 1 if prediction == true_label else -1
        self.correct_predictions += 1 if reward == 1 else 0
        self.total_predictions += 1
        accuracy = self.correct_predictions / self.total_predictions
        print(f"RL Reward: {reward}, Current Accuracy: {accuracy:.2f}")
        return reward

rl_agent = RLAgent()