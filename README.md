# x-weird-for

**HTTP Header Anomaly Detection Using ML and Heuristics**

A security analysis tool that combines machine learning (Isolation Forest) with rule-based heuristics to identify anomalous HTTP headers in logs and traffic.

-----

## Overview

x-weird-for uses a dual approach to detect suspicious HTTP headers:

- **Isolation Forest:** Machine learning anomaly detection (unsupervised ML) [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- **Heuristics Engine:** Rule-based detection for known attack patterns, encoding anomalies, and structural issues
- **Ensemble Models:** Multiple models with different 'personalities' for improved accuracy
- **Rich analysis:** Detailed risk scoring, mutation detection, and entropy analysis

## Key Features
- 35+ engineered features from HTTP headers
- Dual detection combining ML scores with heuristic rules
- Comprehensive evaluation with ROC curves, confusion matrices, and F1 optimization
- Flexible architecture supporting single or ensemble models
- Grid serach optimization for hyperparameter tuning
- Built in Python

-----

## Installation

### Requirements

* Python 3.10+
* scikit-learn, numpy, matplotlib (see requirements.txt)

## Quickstart

### Clone the repo

```
git clone https://github.com/DryHop2/x-weird-for.git
cd x-weird-for

pip install -r requirements.txt
```

**Optional: Run with Docker**
If you prefer Docker, the files (Dockerfile, docker-compose.yml, and .devcontainer/) I used are in the repo for setup or just launch it in your own container.

```docker-compose run dev```

### 1. Train a model

```
# Train on normal traffic
python3 -m scripts.train_iforest --input data/training/training_set.json

# Or train an ensemble for better accuracy
python3 -m scripts.train_ensemble --input data/training/training_set.json
```

### 2. Make Predictions

```
# Analyze a single header ste
python3 -m scripts.predict --input data/test/bad_request.json --model models/model.pkl

# Analyze with verbose output
python3 -m scripts.predict --input data/test/bad_request.json --model models/ensemble.pkl --verbose

# Save results
python3 -m scripts.predict --input data/test/bad_request.json --model models/model.pkl --save-output auto
```

### 3. Evaluate Performance

```
# Evaluate model on labeled data
python3 scripts.eval_model --model models/model.pkl --input data/evaluation/eval_labeled.json

# Find optimal parameters
python3 scipts.grid_serach_iforest --input data/evaluation/eval_labeled.json --save-best
```

-----

### Example Inputs
All examples are in examples/ by default:
- good_request.json (single good header)
- bad_request.json (single bad header)
- gray_request.json (bulk mixed requests)
- eval_labeled.json (with truth labels for testing)

### Default project structure

```
x-weird-for/
├── xweirdfor/                 # Core modules
│   ├── extract_features.py   # Feature engineering (35+ features)
│   └── heuristics.py         # Rule-based detection engine
│
├── scripts/                   # CLI tools
│   ├── predict.py            # Main prediction interface
│   ├── train_iforest.py      # Single model training
│   ├── train_ensemble.py     # Ensemble model training
│   ├── eval_model.py         # Model evaluation & visualization
│   └── grid_search_iforest.py # Hyperparameter optimization
│
├── data/                      # Organized data
│   ├── training/             # Training datasets
│   ├── evaluation/           # Labeled evaluation data
│   └── test/                 # Test samples
│
├── models/                    # Saved models
│   ├── model.pkl             # Single model
│   ├── best_model.pkl        # Grid search optimized
│   └── ensemble.pkl          # Ensemble model
│
└── results/                   # Analysis outputs
    ├── evaluation/           # Performance metrics & plots
    ├── grid_search/          # Optimization results
    └── predictions/          # Saved predictions
```
-----

## Why this project
HTTP headers can be a rich source of telemetry for anomaly detection.
* Automated attacks
* Bots and scrapers
* Misconfigured clients
This tool is designed to give analysts a fast, explainable way to flag unusual or weird headers without only the use of manual inspection through logs.

-----

## How It Works

### Feature Extraction

The system extracts 35+ features from HTTP headers:
* Header presence/absence with weighted importance
* User-Agent analysis: entropy, character diversity, pattern matching
* Statistical features: value lengths, standard deviation
* Structural analysis: header order, case consistency
* Anomaly indicators: encoding issues, injection attempts

### Detection Approach

1. ML Score: Isolation Forest identifies statistical anomalies
2. Heuristic Risk: Rules detect known attack patterns
3. Combined Verdict: Intelligent combination of both approaches
4. Gray Zone: Ensemble disagreement triggers human review

### Risk Scoring

* Low Risk (<0.3): Likely benign
* Medium Risk (0.3 - 0.6): Suspicious, worth investigating
* High Risk (> 0.6): Likely malicious

-----

## Example Detections

* cURL/wget/python-requests user agents
* Missing critical headers (Host, User-Agent)
* Header injection attempts (CRLF)
* Suspicious encoding (double URL encoding)
* IP anomalies (private IPs in public context)
* Mutation/typo detection in header names

-----

## Roadmap 

### Completed

* Isolation Forest ML model
* Basic heuristic engine
* CLI interface
* Grid search optimization
* Ensemble model support
* Enhanced feature engineering (35+ features)
* Entropy and mutation scoring
* Comprehensive evaluation metrics

### In Progress

* Database integration for sample storage
* Community pattern learning
* Real-time monitorin capabilities

### Future

* Web UI for analysis
* SIEM integration (CEF/LEEF export)
* Active learning from analyst feedback
* Rate limiting detection
* Session tracking across multiple requests
* Geographic anomaly detection
* TLS fingerprinting integration

-----

## Contributing

Contributions welcome! Areas of interest:

* Additional heuristic patterns
* Performance optimizations
* Integration with security tools
* Documentation improvements

-----

## License

-----

## Acknowledgments

Built for the [Boot.dev](https://www.boot.dev/) 3-Day Hackathon (2025-07-25 -- 2025-07-28)