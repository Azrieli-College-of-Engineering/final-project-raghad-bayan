import subprocess
import sys
import time

ATTACKS = {
    "1": {
        "label": "CL.TE Request Smuggling",
        "cmd":   ["python", "smuggle_clte.py"],
        "desc":  "Front-end uses Content-Length, back-end uses Transfer-Encoding.",
    },
    "2": {
        "label": "TE.CL Request Smuggling",
        "cmd":   ["python", "smuggle_tecl.py"],
        "desc":  "Front-end uses Transfer-Encoding, back-end uses Content-Length.",
    },
    "3": {
        "label": "Cache Poisoning (CL.TE chain)",
        "cmd":   ["python", "cache_poison.py"],
        "desc":  "Smuggle a privileged request that poisons the shared Varnish cache.",
    },
    "4": {
        "label": "Host Header Injection",
        "cmd":   ["python", "host_header_injection.py"],
        "desc":  "Inject X-Forwarded-Host to hijack password reset links.",
    },
    "5": {
        "label": "Cache Deception",
        "cmd":   ["python", "cache_deception.py"],
        "desc":  "Trick Varnish into caching a private page as a public static asset.",
    },
    "6": {
        "label": "Verify Cache Poisoning",
        "cmd":   ["python", "verify_poison.py"],
        "desc":  "Send multiple GET /api/user and report POISONED vs CLEAN.",
    },
    "7": {
        "label": "Purge Cache",
        "cmd":   ["python", "purge_cache.py"],
        "desc":  "Send PURGE to Varnish to remove a poisoned cache entry.",
    },
}


def print_menu():
    print("\n" + "="*62)
    print("  Web Security Lab — Attack Demo Runner")
    print("="*62)
    for key, attack in ATTACKS.items():
        print(f"  [{key}] {attack['label']}")
        print(f"       {attack['desc']}")
    print("  [A] Run ALL attacks in sequence")
    print("  [Q] Quit")
    print("="*62)


def run_attack(key):
    attack = ATTACKS[key]
    print(f"\n{'='*62}")
    print(f"  Running: {attack['label']}")
    print(f"{'='*62}\n")
    subprocess.run(attack["cmd"])
    print(f"\n[Done] {attack['label']}")


def run_all():
    print("\n=== Running ALL attacks in sequence ===")
    print("Starting in 3 seconds...\n")
    time.sleep(3)

    for key in ATTACKS:
        run_attack(key)
        print("\nWaiting 2 seconds before next attack...")
        time.sleep(2)

    print("\n" + "="*62)
    print("  All attacks completed.")
    print("  Run purge_cache.py to clean up any poisoned entries.")
    print("="*62)


def main():
    if len(sys.argv) > 1 and sys.argv[1].upper() == "ALL":
        run_all()
        return

    while True:
        print_menu()
        choice = input("\n  Select: ").strip().upper()

        if choice == "Q":
            print("Goodbye.")
            break
        elif choice == "A":
            run_all()
        elif choice in ATTACKS:
            run_attack(choice)
        else:
            print("  Invalid choice — try again.")


if __name__ == "__main__":
    main()