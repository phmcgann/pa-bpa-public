import os

# Tests never reach the Palo Alto Networks advisory feed; tests that need advisories set them directly.
os.environ.setdefault("PAN_ADVISORY_FEED", "off")
