import bcrypt
import psycopg2
from database import db_manager

class UserModel:
    def __init__(self):
        self.db = db_manager

    def create_user(self, nome, email, senha):
        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur = self.db.get_cursor()
        try:
            cur.execute("INSERT INTO usuarios (nome, email, senha) VALUES (%s, %s, %s)", 
                       (nome, email, senha_hash))
            self.db.commit()
            return True, None
        except psycopg2.errors.UniqueViolation:
            self.db.rollback()
            return False, 'E-mail já cadastrado!'
        except Exception as e:
            self.db.rollback()
            return False, str(e)

    def get_user_by_email(self, email):
        cur = self.db.get_cursor()
        cur.execute('SELECT id, senha FROM usuarios WHERE email = %s', (email,))
        return cur.fetchone()

    def update_password(self, email, nova_senha):
        senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur = self.db.get_cursor()
        cur.execute("UPDATE usuarios SET senha = %s WHERE email = %s", (senha_hash, email))
        if cur.rowcount == 0:
            return False
        self.db.commit()
        return True

    @staticmethod
    def verify_password(senha, senha_hash):
        return bcrypt.checkpw(senha.encode('utf-8'), senha_hash.encode('utf-8'))