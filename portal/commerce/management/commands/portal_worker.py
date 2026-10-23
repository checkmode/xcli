import signal
import time

from django.core.management.base import BaseCommand
from commerce.worker import tick, require_worker


class Command(BaseCommand):
    help = "Process sandbox checkout, callback delivery, and durable provisioning jobs"

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        require_worker()
        stopping = False

        def stop(*_):
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not stopping:
            try:
                count = tick()
                if options["once"]:
                    self.stdout.write(f"Processed {count} items")
                    return
            except Exception as exc:
                # Never log provider payloads, credentials, or subscription URLs.
                self.stderr.write(f"Worker retry: {type(exc).__name__}")
                if options["once"]:
                    raise
            time.sleep(1)
