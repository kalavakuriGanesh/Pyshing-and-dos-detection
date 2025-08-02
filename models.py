import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score
from datetime import datetime

class SecurityLogger:
    def __init__(self):
        self.logs = []

    def log(self, event_type, details, threat_level='info'):
        self.logs.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'details': details,
            'threat_level': threat_level
        })

    def get_recent_logs(self, n=5):
        return sorted(self.logs, key=lambda x: x['timestamp'], reverse=True)[:n]

class PhishingDetector:
    def __init__(self):
        self.logger = SecurityLogger()
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        self._train_models()

    def _train_models(self):
        # Load and preprocess training data
        data = pd.read_csv('data/phishing_data.csv')
        X = data.drop('label', axis=1)
        y = data['label']

        # Split data into training and testing sets
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train both models
        self.rf_model.fit(X_train, y_train)
        self.gb_model.fit(X_train, y_train)

        # Evaluate accuracy on the test set
        rf_predictions = self.rf_model.predict(X_test)
        gb_predictions = self.gb_model.predict(X_test)

        rf_accuracy = accuracy_score(y_test, rf_predictions)
        gb_accuracy = accuracy_score(y_test, gb_predictions)

        print(f"Phishing Detection - Random Forest Accuracy: {rf_accuracy * 100:.2f}%")
        print(f"Phishing Detection - Gradient Boosting Accuracy: {gb_accuracy * 100:.2f}%")

    def _extract_features(self, url):
        features = {
            'url_length': len(url),
            'https_present': 1 if 'https' in url else 0,
            'suspicious_chars': sum(c in '!@#$%^&*()' for c in url),
            'ip_in_domain': 1 if any(c.isdigit() for c in url.split('.')[0]) else 0,
            'dots_count': url.count('.'),
            'digits_ratio': sum(c.isdigit() for c in url) / len(url),
            'special_chars_ratio': sum(not c.isalnum() for c in url) / len(url),
            'subdomain_level': len(url.split('.')) - 1
        }
        return [features[f] for f in ['url_length', 'https_present', 'suspicious_chars', 'ip_in_domain', 
                                    'dots_count', 'digits_ratio', 'special_chars_ratio', 'subdomain_level']]

    def predict(self, url):
        # Extract features
        features = self._extract_features(url)
        
        # Get predictions from both models
        rf_pred = self.rf_model.predict([features])[0]
        rf_prob = self.rf_model.predict_proba([features])[0][1]
        gb_pred = self.gb_model.predict([features])[0]
        gb_prob = self.gb_model.predict_proba([features])[0][1]
        
        # Ensemble prediction (average of probabilities)
        ensemble_prob = (rf_prob + gb_prob) / 2
        is_phishing = ensemble_prob > 0.5
        
        # Log the prediction
        self.logger.log(
            'Phishing Detection',
            f'URL analyzed: {url} - {"Phishing" if is_phishing else " Safe"}',
            'danger' if is_phishing else 'safe'
        )
        
        # Get feature importance
        feature_names = ['URL Length', 'HTTPS Present', 'Suspicious Chars', 'IP in Domain',
                        'Dots Count', 'Digits Ratio', 'Special Chars Ratio', 'Subdomain Level']
        importances = (self.rf_model.feature_importances_ + self.gb_model.feature_importances_) / 2
        
        return {
            'is_phishing': is_phishing,
            'confidence': round(ensemble_prob * 100, 2),
            'message': 'Potential phishing URL detected!' if is_phishing else 'URL appears to be  safe.',
            'model_comparison': {
                'random_forest': {'prediction': bool(rf_pred), 'confidence': round(rf_prob * 100, 2)},
                'gradient_boosting': {'prediction': bool(gb_pred), 'confidence': round(gb_prob * 100, 2)}
            },
            'features': [{'name': name, 'importance': imp, 'value': val} 
                        for name, imp, val in zip(feature_names, importances, features)]
        }

class DDoSDetector:
    def __init__(self):
        self.logger = SecurityLogger()
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        self._train_models()

    def _train_models(self):
        # Load and preprocess training data
        data = pd.read_csv('data/cicddos2019_data.csv')
        X = data.drop(['label', 'attack_type'], axis=1)  # Drop unnecessary columns
        y = data['attack_type']  # Use attack_type for multi-class classification

        # Split data into training and testing sets
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train both models
        self.rf_model.fit(X_train, y_train)
        self.gb_model.fit(X_train, y_train)

        # Evaluate accuracy on the test set
        rf_predictions = self.rf_model.predict(X_test)
        gb_predictions = self.gb_model.predict(X_test)

        rf_accuracy = accuracy_score(y_test, rf_predictions)
        gb_accuracy = accuracy_score(y_test, gb_predictions)

        print(f"DDoS Detection - Random Forest Accuracy: {rf_accuracy * 100:.2f}%")
        print(f"DDoS Detection - Gradient Boosting Accuracy: {gb_accuracy * 100:.2f}%")

    def predict(self, features):
        # Get predictions from both models
        rf_pred = self.rf_model.predict([features])[0]
        rf_prob = max(self.rf_model.predict_proba([features])[0])  # Max probability for the predicted class
        gb_pred = self.gb_model.predict([features])[0]
        gb_prob = max(self.gb_model.predict_proba([features])[0])  # Max probability for the predicted class

        # Ensemble prediction (average of probabilities)
        ensemble_prob = (rf_prob + gb_prob) / 2
        attack_type = rf_pred if rf_prob > gb_prob else gb_pred  # Choose the model with higher confidence

        # Log the prediction
        self.logger.log(
            'DDoS Detection',
            f'Traffic analyzed: {features[0]} packets/sec - Attack Type: {attack_type}',
            'danger' if attack_type != 'Normal' else 'safe'
        )

        # Get feature importance
        feature_names = ['Packet Rate', 'Byte Rate']
        importances = (self.rf_model.feature_importances_ + self.gb_model.feature_importances_) / 2

        return {
            'attack_type': attack_type,
            'confidence': round(ensemble_prob * 100, 2),
            'message': f'Detected DDoS attack: {attack_type}' if attack_type != 'Normal' else 'Traffic is normal.',
            'model_comparison': {
                'random_forest': {'prediction': rf_pred, 'confidence': round(rf_prob * 100, 2)},
                'gradient_boosting': {'prediction': gb_pred, 'confidence': round(gb_prob * 100, 2)}
            },
            'features': [{'name': name, 'importance': imp, 'value': val} 
                        for name, imp, val in zip(feature_names, importances, features)]
        }

# Initialize detectors 
phishing_detector = PhishingDetector()
ddos_detector = DDoSDetector()
