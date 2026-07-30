#!/usr/bin/env python3

import argparse
from argparse import RawTextHelpFormatter

DEFAULT_WORDS = [
	# IT-specific seed words
    "security",
    "secure",
    "infosec",
    "information",
    "technology",
    "tech",
    "it",
    "cyber",
    "admin",
    "administrator",
    "support",
    "service",
    "helpdesk",
    "desktop",
    "network",
    "networks",
    "wireless",
    "wifi",
    "firewall",
    "router",
    "switch",
    "gateway",
    "proxy",
    "vpn",
    "remote",
    "access",
    "cloud",
    "azure",
    "microsoft",
    "office",
    "m365",
    "o365",
    "windows",
    "linux",
    "server",
    "domain",
    "active",
    "directory",
    "ad",
    "ldap",
    "sso",
    "saml",
    "oauth",
    "password",
    "pass",
    "login",
    "portal",
    "user",
    "users",
    "staff",
    "employee",
    "corp",
    "corporate",
    "internal",
    "external",
    "guest",
    "public",
    "private",
    "prod",
    "production",
    "dev",
    "test",
    "uat",
    "staging",
    "backup",
    "database",
    "data",
    "app",
    "apps",
    "application",
    "system",
    "systems",
    "monitor",
    "logging",
    "audit",
    "compliance",
    "risk",
    "threat",
    "defence",
    "protect",
    "identity",
    "endpoint",
    "email",
    "mail",
    "exchange",
    "sharepoint",
    "teams",
    "intune",
    "entra",
    "defender",
    "sentinel",
    "siem",
    "soc",
    "noc",
    # Common seed words frequently used in guest, home and business WiFi passwords
    "welcome",
    "welcomewifi",
    "welcomehome",
    "welcomeguest",
    "guest",
    "guests",
    "guestaccess",
    "guestnetwork",
    "guestinternet",
    "guestwifi",
    "visitor",
    "visitors",
    "visitorwifi",
    "internet",
    "connect",
    "connected",
    "connection",
    "stayconnected",
    "online",
    "getonline",
    "freewifi",
    "openwifi",
    "wifiaccess",
    "wificode",
    "wifipassword",
    "network",
    "networkname",
    "password",
    "passcode",
    "accesscode",
    "letmein",
    "changeme",
    "default",
    "defaultwifi",
    "home",
    "homewifi",
    "house",
    "housewifi",
    "officewifi",
    "business",
    "businesswifi",
    "company",
    "companywifi",
    "reception",
    "lobby",
    "meeting",
    "meetingroom",
    "boardroom",
    "conference",
    "conferencewifi",
    "training",
    "trainingroom",
    "classroom",
    "student",
    "students",
    "teacher",
    "teachers",
    "school",
    "schoolwifi",
    "campus",
    "campuswifi",
    "hotel",
    "hotelwifi",
    "motel",
    "motelwifi",
    "airbnb",
    "rental",
    "holiday",
    "holidaywifi",
    "cafe",
    "cafewifi",
    "coffee",
    "coffeewifi",
    "restaurant",
    "restaurantwifi",
    "bar",
    "barwifi",
    "shop",
    "shopwifi",
    "store",
    "storewifi",
    "retail",
    "retailwifi",
    "customer",
    "customers",
    "customerwifi",
    "member",
    "members",
    "memberwifi",
    "family",
    "familywifi",
    "friends",
    "friendly",
    "sunshine",
    "summer",
    "winter",
    "spring",
    "autumn",
    "football",
    "baseball",
    "dragon",
    "monkey",
    "princess",
    "charlie",
    "hunter",
    "shadow",
    "trustno1",
    "masterkey",
    "opensesame",
    "helloworld",
    # WiFi and wireless-specific seed words
    "wlan",
    "lan",
    "ssid",
    "wifi",
    "wireless",
    "wirelesslan",
    "internet",
    "hotspot",
    "captive",
    "captiveportal",
    "portalwifi",
    "staffwifi",
    "employeewifi",
    "corporatewifi",
    "corpwifi",
    "companywifi",
    "businesswifi",
    "officewifi",
    "guestwifi",
    "visitorwifi",
    "customerwifi",
    "publicwifi",
    "privatewifi",
    "securewifi",
    "internalwifi",
    "externalwifi",
    "freewifi",
    "openwifi",
    "homewifi",
    "familywifi",
    "schoolwifi",
    "campuswifi",
    "studentwifi",
    "hotelwifi",
    "motelwifi",
    "holidaywifi",
    "cafewifi",
    "coffeewifi",
    "restaurantwifi",
    "retailwifi",
    "shopwifi",
    "storewifi",
    "memberwifi",
    "conferencewifi",
    "trainingwifi",
    "meetingwifi",
    "boardroomwifi",
    "receptionwifi",
    "lobbywifi",
    "eventwifi",
    "accesspoint",
    "accesspoints",
    "ap",
    "router",
    "modem",
    "gateway",
    "mesh",
    "bridge",
    "controller",
    "uplink",
    "backhaul",
    "roaming",
    "antenna",
    "radio",
    "client",
    "clients",
    "device",
    "devices",
    "unifi",
    "ubiquiti",
    "meraki",
    "cisco",
    "aruba",
    "ruckus",
    "fortinet",
    "fortigate",
    "sophos",
    "watchguard",
    "mikrotik",
    "netgear",
    "tplink",
    "linksys",
    "dlink",
    "draytek",
    "asus",
    "belkin",
    "huawei",
    "netcomm",
    "netcommwireless",
    "telstra",
    "optus",
    "vodafone",
    "tpg",
    "iinet",
    "aussiebroadband",
    "superloop",
    "nbn",
    "broadband",
    "fibre",
]
]

SYMBOLS = ["!", "@", "?", "#", "$"]

COMMON_NUMBERS = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "10", "11", "12", "13", "20, "21", "22", "23", "24", "25",  
    "26", "27", "42", "67", "69", "88", "99"
]

LEET_REPLACEMENTS = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
}

MIN_OUTPUT_LENGTH = 9


def load_words(path):
    words = []

    if path:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word:
                    words.append(word)

    words.extend(DEFAULT_WORDS)

    seen = set()
    cleaned = []

    for word in words:
        word = word.strip()
        if not word:
            continue

        key = word.lower()
        if key in seen:
            continue

        seen.add(key)
        cleaned.append(word)

    return cleaned


def leet_word(word):
    output = word.lower()

    for original, replacement in LEET_REPLACEMENTS.items():
        output = output.replace(original, replacement)

    return output


def word_variants(word):
    lower = word.lower()
    title = lower.capitalize()
    upper = lower.upper()

    leet_lower = leet_word(lower)
    leet_title = leet_lower.capitalize()
    leet_upper = leet_lower.upper()

    variants = [
        lower,
        title,
        upper,
        leet_lower,
        leet_title,
        leet_upper,
    ]

    seen = set()
    output = []

    for variant in variants:
        if variant not in seen:
            seen.add(variant)
            output.append(variant)

    return output


def emit(candidate, output_file, seen, max_lines):
    if not candidate:
        return False

    if len(candidate) < MIN_OUTPUT_LENGTH:
        return False

    if candidate in seen:
        return False

    seen.add(candidate)
    output_file.write(candidate + "\n")

    if max_lines and len(seen) >= max_lines:
        return True

    return False


def generate_for_word(word, output_file, seen, max_lines):
    variants = word_variants(word)

    for w in variants:
        if emit(w, output_file, seen, max_lines):
            return True

        for symbol in SYMBOLS:
            if emit(f"{w}{symbol}", output_file, seen, max_lines):
                return True

        for n in range(100):
            n = str(n)

            candidates = [
                f"{n}{w}",
                f"{w}{n}",
            ]

            for symbol in SYMBOLS:
                candidates.extend([
                    f"{n}{w}{symbol}",
                    f"{w}{symbol}{n}",
                ])

            for candidate in candidates:
                if emit(candidate, output_file, seen, max_lines):
                    return True

        if emit(f"{w}{w}", output_file, seen, max_lines):
            return True

        for symbol in SYMBOLS:
            candidates = [
                f"{w}{symbol}{w}",
                f"{w}{symbol}{w}{symbol}",
            ]

            for candidate in candidates:
                if emit(candidate, output_file, seen, max_lines):
                    return True

        for n in COMMON_NUMBERS:
            candidates = [
                f"{n}{w}{n}{w}",
                f"{n}{w}!{n}{w}!",
                f"{n}{w}@{n}{w}@",
                f"{n}{w}?{n}{w}?",
                f"{w}{n}{w}",
                f"{w}!{n}{w}!",
            ]

            for candidate in candidates:
                if emit(candidate, output_file, seen, max_lines):
                    return True

        for n1 in COMMON_NUMBERS:
            for n2 in COMMON_NUMBERS:
                candidates = [
                    f"{n1}{w}!{n2}{w}!",
                    f"{n1}{w}@{n2}{w}@",
                    f"{n1}{w}?{n2}{w}?",
                ]

                for candidate in candidates:
                    if emit(candidate, output_file, seen, max_lines):
                        return True

    return False


def main():
    parser = argparse.ArgumentParser(
        prog="wifi-wordlist.py",
        description="Generate controlled IT and WiFi-themed WPA/WPA2/WPA3 wordlist permutations.",
        formatter_class=RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 wifi-wordlist.py\n"
            "  python3 wifi-wordlist.py -o wordlist.txt\n"
            "  python3 wifi-wordlist.py -w custom-seeds.txt -o engagement-wordlist.txt\n"
            "  python3 wifi-wordlist.py -w client-seeds.txt --max-lines 500000\n"
            "\n"
            "Custom seed list format:\n"
            "  One seed word per line.\n"
            "  Custom seed words are prepended to the built-in seed list.\n"
            "  This means custom words are permutated first.\n"
            "\n"
            "Example custom-seeds.txt:\n"
            "  company\n"
            "  companywifi\n"
            "  guestwifi\n"
            "  staffwifi\n"
            "  buildingname\n"
			"  streetname\n"
            "\n"
            "Output rules:\n"
            "  Duplicate candidates are removed.\n"
            "  Final candidates shorter than 9 characters are not written.\n"
            "  This ensures all written candidates are longer than 8 characters."
        ),
    )

    parser.add_argument(
        "-w",
        "--words",
        help="Optional custom seed word file. One word per line. Custom seeds are prepended to the built-in seed list.",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="wordlist.txt",
        help="Output file. Default: wordlist.txt",
    )

    parser.add_argument(
        "--max-lines",
        type=int,
        default=0,
        help="Maximum number of unique candidates to write. Default: 0 means unlimited.",
    )

    args = parser.parse_args()

    words = load_words(args.words)
    seen = set()

    with open(args.output, "w", encoding="utf-8", errors="ignore") as output_file:
        for word in words:
            stop = generate_for_word(
                word=word,
                output_file=output_file,
                seen=seen,
                max_lines=args.max_lines,
            )

            if stop:
                break

    print(f"Wrote {len(seen)} unique candidates to {args.output}")


if __name__ == "__main__":
    main()
