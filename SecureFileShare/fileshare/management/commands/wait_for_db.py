import time

from psycopg2 import OperationalError as psycopg2OpError

from django.db import connections
from django.db.utils import OperationalError
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    """Django command to wait for database"""

    def handle(self, *args, **options):
        """Entrypoint for the command"""
        self.stdout.write('Waiting for the Database')
        db_up = False
        while not db_up:
            try:
                connection = connections['default']
                connection.ensure_connection()
                db_up = True
            except (psycopg2OpError, OperationalError):
                self.stdout.write("Database Unavailable, waiting for 1 second...")
                time.sleep(1)

        self.stdout.write(self.style.SUCCESS("Database is ready"))
