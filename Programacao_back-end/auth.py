import jwt
import datetime
from functools import wraps
from flask import request, jsonify
from config import Config

class JWTManager:
    @staticmethod
    def encode_token(user_id, email):
        payload = {
            'id': user_id,
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

    @staticmethod
    def decode_token(token):
        try:
            return jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            print("[auth] Token expirado.")
            return None
        except jwt.InvalidTokenError as e:
            print(f"[auth] Token inválido: {e}")
            return None

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw = request.headers.get('Authorization', '')

        # Log para diagnóstico — mostra os primeiros 60 chars do header recebido
        print(f"[auth] Authorization header recebido: '{raw[:60]}'")

        # Remove prefixo 'Bearer ' caso algum cliente o envie
        token = raw[7:] if raw.lower().startswith('bearer ') else raw
        token = token.strip()

        if not token:
            return jsonify({'erro': 'Token não fornecido'}), 401

        decoded = JWTManager.decode_token(token)
        if not decoded:
            return jsonify({'erro': 'Token inválido'}), 401

        request.user_id = decoded['id']
        return f(*args, **kwargs)
    return decorated

# Função original do seu código
def get_user_id_from_token(token):
    if not token:
        return None
    # Remove prefixo 'Bearer ' se existir
    if token.lower().startswith('bearer '):
        token = token[7:].strip()
    try:
        decoded = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return decoded.get('id') or decoded.get('sub')
    except Exception as e:
        print(f"[get_user_id_from_token] Erro: {e}")
        return None