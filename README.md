# x-weird-for

**HTTP Header Anomaly Detection Using ML and Heuristics**
Built for the Boot.dev 3-Day Hackathon (2025-07-25 -- 2025-07-28)

-----

## Overview

- **Isolation Forest** anomaly detection (unsupervised ML)
- **Heuristics** for identifying uncommon headers, suspicious user-agents, and missing expected headers
- Evaluation tools to test and optimize model performance, including grid search optimization
- Built in Python

-----

## Quickstart

### 1. Clone the repo
```git clone https://github.com/DryHop2/x-weird-for.git```

cd x-weird-for

### 2. Set up (Docker or local)
Using Python 3.10+

```pip install -r requirements.txt```

**Optional: Run with Docker**
If you prefer Docker, the files (Dockerfile, docker-compose.yml, and .devcontainer/) I used are in the repo for setup or just launch it in your own container.
(NOTE: If you have to set up Docker from the start, this may exceed the 5 minute start time constraint of the Hackathon)
```docker-compose run dev```

### 3. Run a test
```python3 -m scripts.predict --input examples/good_request.json```

or bulk test

```python3 -m scripts.predict --input examples/gray_request.json```

-----

## Features

- Parse and evaluate headers for anomalies
- Isolation Forest Machine Learning model [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- Heuristics for static pattern detection
- eval_model to measure F1 score, recall, and accuracy
- grid_search_iforest for automated model optimization
- Tunable CLI options for thresholds, models, and inputs

### Example Inputs
All examples are in examples/ by default:
- good_request.json (single good header)
- bad_request.json (single bad header)
- gray_request.json (bulk mixed requests)
- eval_labeled.json (with truth labels for testing)

### Default project structure
```
x-weird-for/
│
├── xweirdfor/              # Core feature + heuristic code
├── scripts/                # CLI interfaces (predict, train, grid search)
├── models/                 # Saved models
├── examples/               # Sample headers for testing
├── tests/                  # Pytest unit tests
├── requirements.txt
└── README.md
```

## Why this project
HTTP headers can be a rich source of telemetry for anomaly detection.
* Automated attacks
* Bots and scrapers
* Misconfigured clients
This tool is designed to give analysts a fast, explainable way to flag unusual or weird headers without only the use of manual inspection through logs.

## Roadmap (Post-hackathon goals)
* Add entropy and mutation scoring
* Extend heuristics with community data
* Build out, store, and analyze header samples in a database
* Additional model tuning and output
* Browser accessible UI (maybe)