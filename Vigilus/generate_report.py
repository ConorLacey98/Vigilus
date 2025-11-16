import argparse
from core.db import init_db
from core.reporting import generate_advisory_docx

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-id", type=int, required=True, help="ID of the event to generate an advisory for")
    args = parser.parse_args()

    init_db()
    output = generate_advisory_docx(args.event_id)
    print(f"Generated advisory: {output}")

if __name__ == "__main__":
    main()
