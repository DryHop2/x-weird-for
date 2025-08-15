from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import warnings
warnings.filterwarnings('ignore')


def train_ensemble_model(features, args):
    """
    Train an ensemble of Isolation Forest models with different parameters.
    """
    models = []

    # Train multiple models with different random states and parameters
    param_sets = [
        {"n_estimators": 100, "contamination": 0.1, "max_features": 1.0},
        {"n_estimators": 150, "contamination": 0.05, "max_features": 0.8},
        {"n_estimators": 200, "contamination": 0.15, "max_features": 0.6},
    ]

    for i, params in enumerate(param_sets):
        model = IsolationForest(
            n_estimators=params["n_estimators"],
            contamination=params["contamination"],
            max_features=params["max_features"],
            random_state=42 + i,
            n_jobs=-1
        )
        model.fit(features)
        models.append(model)

    # Also train the main model
    main_model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        max_features=args.max_features,
        random_state=42,
        bootstrap=True,
        n_jobs=-1
    )
    main_model.fit(features)

    return {
        "main_model": main_model,
        "ensemble": models,
        "scaler": None, # Will be set if scaling is used
        "pca": None # Will be set if PCA is used
    }