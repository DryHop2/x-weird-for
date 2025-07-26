import joblib

from extract_features import extract_features


def load_model(model_path):
    return joblib.load(model_path)


def run_prediction(model, header_dict):
    features = extract_features(header_dict)
    score = model.decision_function([features])[0]
    prediction = model.predict([features])[0]
    verdict = "suspicious" if prediction == -1 else "normal"
    return verdict, score