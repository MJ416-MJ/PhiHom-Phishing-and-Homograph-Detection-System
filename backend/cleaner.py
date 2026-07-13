import csv
import os
import re
import sys
from collections import defaultdict

import tldextract

csv.field_size_limit(sys.maxsize)

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(DATA_DIR, exist_ok=True)

INPUT_PATH = os.path.join(DATA_DIR, "legitimate_domains.csv")
OUTPUT_PATH = os.path.join(DATA_DIR, "legitimate_clean_doms.csv")
SHORTENERS_PATH = os.path.join(DATA_DIR, "url_shorteners.txt")

OUT_STEM = os.path.splitext(OUTPUT_PATH)[0]
REMOVED_PATH = f"{OUT_STEM}_removed.csv"
REVIEW_PATH = f"{OUT_STEM}_review.csv"

ext = tldextract.TLDExtract(suffix_list_urls=())

# ------------------------------------------------------------------
# URL shorteners
# ------------------------------------------------------------------
def load_shorteners(path):
    shorteners = set()

    if not os.path.exists(path):
        print(f"[WARN] Missing shortener list: {path}")
        return shorteners

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()

            if not line:
                continue

            if line.startswith("#"):
                continue

            shorteners.add(line)

    return shorteners


# ------------------------------------------------------------------
# Protected brands
# ------------------------------------------------------------------

PROTECTED_BRANDS = {
    "google","youtube","gmail","gstatic",
    "microsoft","office","windows","outlook","live",
    "apple","icloud",
    "amazon",
    "facebook","meta","instagram","whatsapp","threads",
    "twitter",
    "linkedin",
    "paypal","stripe","visa","mastercard","americanexpress",
    "github","gitlab",
    "dropbox",
    "slack",
    "discord",
    "telegram",
    "reddit",
    "netflix",
    "spotify",
    "steam",
    "epicgames",
    "playstation",
    "xbox",
    "nintendo",
    "roblox",
    "tiktok",
    "snapchat",
    "wechat",
    "qq",
    "baidu",
    "yandex",
    "cloudflare",
    "godaddy",
    "wordpress",
    "shopify",
    "adobe",
    "zoom",
    "oracle",
    "intel",
    "amd",
    "nvidia",
    "vmware",
    "cisco",
    "salesforce",
    "okta",
    "docusign",
    "coinbase",
    "binance",
    "kraken",
    "wise",
    "revolut",
    "westernunion",
    "venmo",
    "fedex",
    "ups",
    "usps",
    "dhl",
    "uber",
    "lyft",
    "airbnb",
    "booking",
    "expedia",
    "ezviz",
    "hikvision",
    "tplink",
    "xiaomi",
    "samsung",
    "sony",
    "lg",
}
USER_FACING_SUBDOMAINS = {
    "www",
    "mail",
    "webmail",
    "login",
    "signin",
    "accounts",
    "myaccount",
    "account",
    "support",
    "help",
    "docs",
    "drive",
    "maps",
    "news",
    "calendar",
    "photos",
    "meet",
    "play",
    "store",
    "translate",
    "blog",
    "developer",
    "developers",
    "community",
    "forum",
    "forums",
    "status",
    "portal",
    "shop",
    "download",
    "downloads",
    "home",
}

INFRASTRUCTURE_SUBDOMAINS = {
      "gvt1",
    "gvt2",
    "gstatic",
    "googleapis",
    "googleusercontent",
    "doubleclick",
    "googlesyndication",
    "googletagmanager",
    "google-analytics",
    "pki",
    "ocsp",
    "crl",
    "redirector",
    "clients",
    "clients1",
    "clients2",
    "clients3",
    "clients4",
    "clients5",
    "clients6",
    "clients7",
    "mtalk",
    "connectivitycheck",
    "adtrafficquality",
    "telemetry",
    "metrics",
    "analytics",
    "collector",
    "proxy",
    "gateway",
    "relay",
    "cache",
    "cdn",
    "edge",
    "api",
    "rpc",
    "backend",
    "internal",
    "health",
    "healthcheck",
    "ping",
    "probe",
    "update",
    "updates",
    "dns",
    "resolver",
    "ns",
    "smtp",
    "imap",
    "mx",
    "storage",
    "bucket",
    "blob",
    
}

PROTECTED_BRANDS = {b.lower() for b in PROTECTED_BRANDS}

# ------------------------------------------------------------------
# Keywords
# ------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "secure",
    "verify",
    "verification",
    "update",
    "password",
    "account",
    "wallet",
    "billing",
    "invoice",
    "support",
    "authenticate",
    "reset",
    "recover",
    "unlock",
    "confirm",
    "session",
    "security",
}

# ------------------------------------------------------------------
# Visual substitutions
# ------------------------------------------------------------------

LEET_MAP = str.maketrans({
    "0":"o",
    "1":"l",
    "3":"e",
    "4":"a",
    "5":"s",
    "6":"g",
    "7":"t",
    "8":"b",
    "9":"g",
})

VISUAL_SUBS = (
    ("rn","m"),
    ("vv","w"),
    ("cl","d"),
    ("ii","n"),
)

def normalize_visual(name):

    name = name.translate(LEET_MAP)

    for old,new in VISUAL_SUBS:
        name = name.replace(old,new)

    return name


# ------------------------------------------------------------------
# Damerau-Levenshtein
# ------------------------------------------------------------------

def edit_distance(a,b,max_dist=2):

    if abs(len(a)-len(b))>max_dist:
        return max_dist+1

    la=len(a)
    lb=len(b)

    prev2=None
    prev=list(range(lb+1))

    for i in range(1,la+1):

        curr=[i]+[0]*lb

        for j in range(1,lb+1):

            cost=0 if a[i-1]==b[j-1] else 1

            curr[j]=min(
                prev[j]+1,
                curr[j-1]+1,
                prev[j-1]+cost
            )

            if (
                i>1
                and j>1
                and a[i-1]==b[j-2]
                and a[i-2]==b[j-1]
            ):
                curr[j]=min(curr[j],prev2[j-2]+cost)

        prev2,prev=prev,curr

    return prev[-1]


# ------------------------------------------------------------------
# Detection
# ------------------------------------------------------------------

def detect_brand_impersonation(name):

    if name in PROTECTED_BRANDS:
        return None

    visual=normalize_visual(name)

    if visual in PROTECTED_BRANDS:
        return "leet / homoglyph"

    dehyphen=name.replace("-","")

    if dehyphen in PROTECTED_BRANDS:
        return "hyphenation"

    for brand in PROTECTED_BRANDS:

        if re.fullmatch(rf"{re.escape(brand)}\d+",name):
            return f"brand '{brand}' + numbers"

        if re.fullmatch(rf"\d+{re.escape(brand)}",name):
            return f"numbers + brand '{brand}'"

        if brand in name and name!=brand:

            if any(word in name for word in SUSPICIOUS_KEYWORDS):
                return f"brand '{brand}' + phishing keyword"

            return f"contains protected brand '{brand}'"

        threshold=0 if len(brand)<=4 else 1 if len(brand)<=6 else 2

        if edit_distance(name,brand,threshold)<=threshold:
            return f"edit distance from '{brand}'"

    return None


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():

    shorteners = load_shorteners(SHORTENERS_PATH)

    stats = defaultdict(int)

    seen = set()

    clean_rows = []
    removed_rows = []

    with open(INPUT_PATH, "r", encoding="utf-8", newline="") as f:

        reader = csv.reader(f)

        for row in reader:

            if len(row) < 2:
                continue

            rank = row[0].strip()
            domain = row[1].strip().lower()
            if domain.startswith("xn--"):

                stats["removed_punycode"] += 1
                removed_rows.append([rank, domain, "punycode"])
                continue

            stats["total"] += 1

            # ---------------------------------------------
            # duplicate
            # ---------------------------------------------

            if domain in seen:

                stats["removed_duplicate"] += 1
                removed_rows.append([rank, domain, "duplicate"])
                continue

            seen.add(domain)

            # ---------------------------------------------
            # URL shortener
            # ---------------------------------------------

            if domain in shorteners:

                stats["removed_shortener"] += 1
                removed_rows.append(
                    [rank, domain, "known URL shortener"]
                )
                continue

            # ---------------------------------------------
            # valid public suffix
            # ---------------------------------------------

            try:
                parts = ext(domain)

            except Exception as e:

                stats["removed_parse_error"] += 1
                removed_rows.append(
                    [rank, domain, f"parse error ({e})"]
                )
                continue

            if not parts.domain or not parts.suffix:

                stats["removed_malformed"] += 1
                removed_rows.append(
                    [rank, domain, "malformed / invalid suffix"]
                )
                continue

            name = parts.domain
            if name in INFRASTRUCTURE_SUBDOMAINS:
                stats["removed_infrastructure"] += 1
                removed_rows.append([rank, domain, "infrastructure domain"])
                continue
            sub = parts.subdomain.lower()

            if sub:

                labels = sub.split(".")

    # Allow common user-facing subdomains.
                if any(label in USER_FACING_SUBDOMAINS for label in labels):
                    pass

    # Remove obvious infrastructure hostnames.
                elif any(label in INFRASTRUCTURE_SUBDOMAINS for label in labels):

                    stats["removed_infrastructure"] += 1
                    removed_rows.append(
                    [rank, domain, "infrastructure hostname"]
                    )
                    continue

            # ---------------------------------------------
            # brand impersonation
            # ---------------------------------------------

            if len(name) > 25:

               stats["removed_long_label"] += 1
               removed_rows.append([rank, domain, "very long label"])
               continue

            digits = sum(c.isdigit() for c in name)

            if digits >= 6:

              stats["removed_many_digits"] += 1
              removed_rows.append([rank, domain, "too many digits"])
              continue
            reason = detect_brand_impersonation(name)

            if reason:

                stats["removed_impersonation"] += 1

                removed_rows.append(
                    [rank, domain, reason]
                )

                continue

            # ---------------------------------------------
            # clean
            # ---------------------------------------------

            clean_rows.append([rank, domain])
            stats["kept_clean"] += 1

    # ----------------------------------------------------
    # write clean list
    # ----------------------------------------------------

    with open(
        OUTPUT_PATH,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.writer(f)
        writer.writerows(clean_rows)

    # ----------------------------------------------------
    # write removed
    # ----------------------------------------------------

    with open(
        REMOVED_PATH,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "rank",
            "domain",
            "reason",
        ])

        writer.writerows(removed_rows)

    # ----------------------------------------------------

    # ----------------------------------------------------
    # summary
    # ----------------------------------------------------

    print("\n========== SUMMARY ==========\n")

    for key in sorted(stats):

        print(f"{key:30} {stats[key]:>10,}")

    print()

    print(f"Clean file   : {OUTPUT_PATH}")
    print(f"Removed file : {REMOVED_PATH}")

    print()
    print(f"Clean domains : {len(clean_rows):,}")
    print(f"Removed       : {len(removed_rows):,}")


if __name__ == "__main__":
    main()