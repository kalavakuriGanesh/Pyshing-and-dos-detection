# AI-Powered Network Security Dashboard

A comprehensive network security monitoring platform that uses AI to detect phishing, anomalies, and DDoS attacks in real-time.

## Features

- **Phishing Detection**: Analyzes URLs using machine learning to identify potential phishing attempts
- **Anomaly Detection**: Monitors network traffic patterns to detect unusual behavior
- **DDoS Detection**: Identifies potential DDoS attacks through traffic analysis
- **Modern UI**: Responsive dashboard built with Dash and Bootstrap

## Dataset Information

The project uses simplified versions of three major cybersecurity datasets:

1. **UCI Phishing Dataset**: Features for URL analysis
2. **CICIDS2017**: Network traffic patterns and anomalies
3. **CICDDoS2019**: DDoS attack patterns

## Setup Instructions

1. Install Python 3.x from [python.org](https://www.python.org/downloads/)

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your web browser and go to:
   ```
   http://127.0.0.1:8050
   ```

## Dashboard Components

### 1. Phishing Detection
- Input: URL for analysis
- Output: Probability of being a phishing attempt
- Visualization: Pie chart showing risk assessment

### 2. Anomaly Detection
- Input: Network traffic metrics
- Output: Normal/Anomaly classification
- Visualization: Bar chart showing traffic analysis

### 3. DDoS Detection
- Input: Packet rate metrics
- Output: DDoS probability
- Visualization: Line chart showing packet rate analysis

### 4. Real-time Network Statistics
- Continuous monitoring of network metrics
- Auto-updating graphs
- Historical trend analysis

## Project Structure

```
network_security_dashboard/
├── data/                      # Datasets
│   ├── phishing_data.csv     # Phishing detection data
│   ├── cicids2017_data.csv   # Anomaly detection data
│   └── cicddos2019_data.csv  # DDoS detection data
├── app.py                     # Main application file
└── requirements.txt          # Python dependencies
```

## Usage Examples

1. **Phishing Detection**:
   - Enter a URL in the input field
   - Click "Analyze"
   - View the risk assessment and visualization

2. **Anomaly Detection**:
   - Input traffic metrics
   - Click "Analyze"
   - Check the anomaly detection results

3. **DDoS Detection**:
   - Enter packet rate information
   - Click "Analyze"
   - Review the DDoS analysis results

## Future Enhancements

1. Integration with live network traffic
2. Advanced machine learning models
3. Additional security metrics
4. Export and reporting features
5. Alert system integration

## Contributing

Feel free to contribute to this project by:
1. Reporting issues
2. Suggesting enhancements
3. Creating pull requests

## License

This project is open source and available under the MIT License.
