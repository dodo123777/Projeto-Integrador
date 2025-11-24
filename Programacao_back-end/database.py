import psycopg2
from config import Config

class DatabaseManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance.conn = None
            cls._instance._connect()
        return cls._instance

    def _connect(self):
        if self.conn is None or self.conn.closed:
            try:
                self.conn = psycopg2.connect(
                    dbname=Config.DB_NAME,
                    user=Config.DB_USER,
                    password=Config.DB_PASSWORD,
                    host=Config.DB_HOST,
                    port=Config.DB_PORT,
                    sslmode="require"  # ← ESSENCIAL pro Supabase
                )
            except psycopg2.Error as e:
                print(f"Erro ao conectar: {e}")
                raise

    def get_cursor(self):
        self._connect()
        return self.conn.cursor()

    def commit(self):
        if self.conn:
            self.conn.commit()

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
            self.conn = None

# Instância global
db_manager = DatabaseManager()
