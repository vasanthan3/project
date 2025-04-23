# PCAP Analyzer + AI Classifier

## Structure
- `data/raw`: Raw PCAPs
- `data/processed`: Parsed traffic (CSV)
- `models`: Trained ML models
- `results`: Graphs & outputs
- `scripts`: Python scripts

## Usage
1. Analyze: `python scripts/analyze_pcap.py`
2. Forecast: `python scripts/traffic_forecast.py`
3. Train Classifier: `python scripts/ip_packet_classifier.py`

## Dependencies
Install using:
```bash
pip install -r requirements.txt
