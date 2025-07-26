import argparse
import json

from predict import load_model, run_prediction


def main():
    parser = argparse.ArgumentParser(description="Analyze HTTP headers for anomalies.")
    parser.add_argument("--input", required=True, help="Path to header JSON file")
    parser.add_argument("--model", default="model.pkl", help="Path to saved model")
    parser.add_argument("--bulk", action="store_true", help="Enable batch mode for multiple header sets")

    args = parser.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    if args.bulk:
        if not isinstance(data, list):
            raise ValueError("Bulk mode requires a list of header objects.")
        header_sets = data
    else:
        if not isinstance(data, dict):
            raise ValueError("Single mode requires a single header object.")
        header_sets = [data]

    model = load_model(args.model)

    for i, headers in enumerate(header_sets):
        verdict, score = run_prediction(model, headers)
        print(json.dumps({
            "index": i,
            "verdict": verdict,
            "score": score
        }, indent=2))


if __name__ == "__main__":
    main()