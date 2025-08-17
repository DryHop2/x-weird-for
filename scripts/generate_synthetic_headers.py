import os
import json
import random
import string
import argparse

COMMON_HEADERS = [
    "Host", "User-Agent", "Accept", "Accept-Encoding", "Connection",
    "Content-Type", "Referer", "X-Forwarded-For"
]

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/139.0.7258.60 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.5; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.158 Mobile Safari/537.36 EdgA/138.0.3351.98",
    "Mozilla/5.0 (Linux; Android 14; Pixel 9 Build/AD1A.240411.003.A5; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.54 Mobile Safari/537.36"
]

BAD_UAS = [
    "curl/7.68.0", "python-requests/2.25.1", "Go-http-client/1.1", "scrapy/1.0.0",
    "evil-bot", "malicious-spider", "wget"
]

UNCOMMON_HEADERS = [
    "X-Evil", "X-Test", "X-Custom-Foo", "DNT", "X-Obfuscate"
]

def random_str(length=12, entropy=False):
    safe_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if entropy:
        return ''.join(random.choices(safe_chars, k=length))
    else:
        return ''.join(random.choices(string.ascii_letters + ' ', k=length))
    

def build_normal_headers():
    headers = {
        "User-Agent": random.choice(BROWSER_UAS),
        "Host": f"{random.choice(['example.com', 'testsite.org', 'mydomain.net'])}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Referer": f"https://{random.choice(['google.com', 'bing.com', 'yahoo.com'])}",
        "X-Forwarded-For": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    return headers


def build_suspicious_headers():
    headers = {}

    # Missing expected headers
    if random.random() < 0.5:
        headers["User-Agent"] = random.choice(BAD_UAS)
    else:
        headers["X-Evil-UA"] = random_str(24)

    if random.random() < 0.7:
        headers["X-Forwarded-For"] = random_str(32, entropy=True)

    # Add junk or uncommon headers
    for _ in range(random.randint(1, 4)):
        key = random.choice(UNCOMMON_HEADERS)
        value = random_str(random.randint(15, 120), entropy=random.random() < 0.5)
        headers[key] = value

    # Occasionally include misleading normal headers
    if random.random() < 0.3:
        headers["Content-Type"] = "application/x-bad-mime-type"

    return headers


def generate_dataset(n_samples=1000, ratio=0.5):
    dataset = []

    n_normal = int(n_samples * ratio)
    n_suspicious = n_samples - n_normal

    for _ in range(n_normal):
        dataset.append({"headers": build_normal_headers(), "label": "normal"})

    for _ in range(n_suspicious):
        dataset.append({"headers": build_suspicious_headers(), "label": "suspicious"})

    random.shuffle(dataset)
    return dataset


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic HTTP header dataset")
    parser.add_argument("--output", default="data/evaluation/synthetic_eval.json", help="Output file path")
    parser.add_argument("--samples", type=int, default=1000, help="Total number of samples")
    parser.add_argument("--ratio", type=float, default=0.5, help="Proportion of normal samples (0.0 - 1.0)")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    data = generate_dataset(n_samples=args.samples, ratio=args.ratio)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Wrote {args.samples} labeled samples to {args.output}")


if __name__ == "__main__":
    main()