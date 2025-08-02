from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from models import phishing_detector, ddos_detector
import datetime
import json
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

app = Flask(__name__)
app.secret_key = '1234qwer'

# Initialize stats
stats = {
    'system_status': 'Active',
    'total_analyses': 0,
    'threats_detected': 0,
    'model_accuracy': 0,
    'last_training': None
}

def analyze_dataset(dataset_path):
    """Analyze a phishing dataset and return insights"""
    try:
        df = pd.read_csv(dataset_path)
        analysis = {
            'total_samples': len(df),
            'feature_names': list(df.columns),
            'phishing_ratio': (df['label'] == 1).mean() if 'label' in df.columns else None,
            'missing_values': df.isnull().sum().to_dict(),
            'feature_stats': df.describe().to_dict(),
        }
        return analysis
    except Exception as e:
        return {'error': str(e)}

def train_model(dataset_path):
    """Train the phishing detection model on a given dataset"""
    try:
        # Load and preprocess data
        df = pd.read_csv(dataset_path)
        
        # Separate features and target
        X = df.drop('label', axis=1) if 'label' in df.columns else df.iloc[:, :-1]
        y = df['label'] if 'label' in df.columns else df.iloc[:, -1]
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train the model
        phishing_detector.train(X_train, y_train)
        
        # Evaluate the model
        y_pred = phishing_detector.predict_batch(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        
        # Generate confusion matrix plot
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig('static/confusion_matrix.png')
        plt.close()
        
        # Update stats
        stats['model_accuracy'] = round(accuracy * 100, 2)
        stats['last_training'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            'accuracy': accuracy,
            'report': report,
            'confusion_matrix': cm.tolist(),
            'feature_importance': phishing_detector.get_feature_importance(X.columns)
        }
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    recent_logs = phishing_detector.logger.get_recent_logs(5)
    return render_template('index.html', stats=stats, recent_logs=recent_logs)

@app.route('/analyze_dataset', methods=['POST'])
def analyze_dataset_route():
    if 'dataset' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['dataset']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    # Save the uploaded file
    dataset_path = Path('uploads') / file.filename
    dataset_path.parent.mkdir(exist_ok=True)
    file.save(str(dataset_path))
    
    # Analyze the dataset
    analysis = analyze_dataset(str(dataset_path))
    session['dataset_analysis'] = analysis
    
    return redirect(url_for('index'))

@app.route('/train_model', methods=['POST'])
def train_model_route():
    if 'dataset' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['dataset']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    # Save the uploaded file
    dataset_path = Path('uploads') / file.filename
    dataset_path.parent.mkdir(exist_ok=True)
    file.save(str(dataset_path))
    
    # Train the model
    results = train_model(str(dataset_path))
    session['training_results'] = results
    
    return redirect(url_for('index'))

@app.route('/analyze_phishing', methods=['POST'])
def analyze_phishing():
    url = request.form['url']
    result = phishing_detector.predict(url)
    
    # Update stats
    stats['total_analyses'] += 1
    if result['is_phishing']:
        stats['threats_detected'] += 1
    
    return render_template('index.html', stats=stats, phishing_result=result,
                         recent_logs=phishing_detector.logger.get_recent_logs(5))

@app.route('/analyze_ddos', methods=['POST'])
def analyze_ddos():
    packet_rate = float(request.form['packet_rate'])
    byte_rate = float(request.form['byte_rate'])
    features = [packet_rate, byte_rate]

    result = ddos_detector.predict(features)

    # Update stats
    stats['total_analyses'] += 1
    if result['attack_type'] != 'Normal':
        stats['threats_detected'] += 1

    return render_template('index.html', stats=stats, ddos_result=result,
                         recent_logs=ddos_detector.logger.get_recent_logs(5))

if __name__ == '__main__':
    # Create uploads directory if it doesn't exist
    Path('uploads').mkdir(exist_ok=True)
    app.run(debug=True)
