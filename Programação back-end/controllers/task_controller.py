from flask import Blueprint, request, jsonify
from models.task import TaskModel
from auth import get_user_id_from_token
import jwt

task_bp = Blueprint('task', __name__)
task_model = TaskModel()

@task_bp.route('/tarefas', methods=['POST'])
def add_task():
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    data = request.get_json()
    texto = data.get('text')
    data_tarefa = data.get('date')
    horario = data.get('time')
    deadline = data.get('deadline')

    task_id = task_model.add_task(user_id, texto, data_tarefa, horario, deadline)
    return jsonify({'id': task_id})

@task_bp.route('/tarefas', methods=['GET'])
def list_tasks():
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    data_tarefa = request.args.get('date')
    tasks = task_model.list_tasks(user_id, data_tarefa)
    return jsonify(tasks)

@task_bp.route('/tarefas/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    task_model.delete_task(task_id, user_id)
    return '', 204

@task_bp.route('/tarefas/<int:task_id>/concluir', methods=['POST'])
def toggle_task(task_id):
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    data = request.get_json()
    completed = data.get('completed', False)

    task_model.toggle_task(task_id, user_id, completed)
    return '', 204

@task_bp.route('/tarefas_protegidas', methods=['GET'])
def tarefas_protegidas():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'erro': 'Token não enviado'}), 401
    try:
        from config import Config
        jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return jsonify({'msg': 'Acesso permitido!'})
    except jwt.ExpiredSignatureError:
        return jsonify({'erro': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'erro': 'Token inválido'}), 401