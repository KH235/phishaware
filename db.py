import os

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


class Connection:
    """
    Thin wrapper around a psycopg2 connection so the rest of the app can keep
    using the same calls it used with MySQL (dictionary=True, is_connected()).
    """

    def __init__(self, raw):
        self._raw = raw

    def cursor(self, dictionary=False, buffered=False):
        # psycopg2 already buffers results on the client, so `buffered` is ignored.
        factory = psycopg2.extras.RealDictCursor if dictionary else None
        return self._raw.cursor(cursor_factory=factory)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        self._raw.close()

    def is_connected(self):
        return not self._raw.closed


def get_db_connection():
    raw = psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.getenv("DB_PORT", "5432")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        dbname=os.environ["DB_NAME"],
        sslmode=os.getenv("DB_SSLMODE", "require"),
        connect_timeout=10,
    )
    return Connection(raw)
