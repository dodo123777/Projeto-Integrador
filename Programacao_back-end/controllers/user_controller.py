from flask import Blueprint, request, jsonify
from models.user import UserModel
from auth import JWTManager

user_bp = Blueprint('user', __name__)
user_model = UserModel()

@user_bp.route('/registrar', methods=['POST'])
def registrar():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not (nome and email and senha):
        return jsonify({'erro': 'Preencha todos os campos!'}), 400

    success, message = user_model.create_user(nome, email, senha)
    if success:
        return jsonify({'msg': 'Usuário registrado com sucesso!'})
    elif message == 'E-mail já cadastrado!':
        return jsonify({'erro': message}), 409
    else:
        return jsonify({'erro': message}), 500

@user_bp.route('/esqueci_senha', methods=['POST'])
def esqueci_senha():
    data = request.get_json()
    email = data.get('email')
    nova_senha = data.get('nova_senha')
    
    if not (email and nova_senha):
        return jsonify({'erro': 'Preencha todos os campos!'}), 400

    if user_model.update_password(email, nova_senha):
        return jsonify({'msg': 'Senha atualizada!'})
    else:
        return jsonify({'erro': 'E-mail não cadastrado!'}), 404

@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')
    
    user = user_model.get_user_by_email(email)
    if user:
        user_id, senha_hash = user
        if UserModel.verify_password(senha, senha_hash):
            token = JWTManager.encode_token(user_id, email)
            return jsonify({'token': token})
    
    return jsonify({'erro': 'Credenciais inválidas'}), 401