from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import bcrypt
import jwt
import datetime

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'SEVEN_2024_SUPERSECRETO'

# Conexão com o PostgreSQL
conn = psycopg2.connect(
    dbname="minha_agenda",
    user="meu_usuario",
    password="1234",
    host="localhost",
    port="5432"
)

# ------------------- UTILITÁRIO JWT ---------------------
def get_user_id_from_token(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return decoded['id']
    except Exception:
        return None

# ------------------- REGISTRO DE USUÁRIO ---------------------
@app.route('/registrar', methods=['POST'])
def registrar():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not (nome and email and senha):
        return jsonify({'erro': 'Preencha todos os campos!'}), 400

    senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO usuarios (nome, email, senha) VALUES (%s, %s, %s)", (nome, email, senha_hash))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        return jsonify({'erro': 'E-mail já cadastrado!'}), 409
    except Exception as e:
        return jsonify({'erro': str(e)}), 500

    return jsonify({'msg': 'Usuário registrado com sucesso!'})

# ------------------- ESQUECI MINHA SENHA ---------------------
@app.route('/esqueci_senha', methods=['POST'])
def esqueci_senha():
    data = request.get_json()
    email = data.get('email')
    nova_senha = data.get('nova_senha')
    if not (email and nova_senha):
        return jsonify({'erro': 'Preencha todos os campos!'}), 400

    senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cur = conn.cursor()
    cur.execute("UPDATE usuarios SET senha = %s WHERE email = %s", (senha_hash, email))
    if cur.rowcount == 0:
        return jsonify({'erro': 'E-mail não cadastrado!'}), 404
    conn.commit()
    return jsonify({'msg': 'Senha atualizada!'})

# ------------------- LOGIN ---------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')
    cur = conn.cursor()
    cur.execute('SELECT id, senha FROM usuarios WHERE email = %s', (email,))
    user = cur.fetchone()
    if user:
        user_id, senha_hash = user
        if bcrypt.checkpw(senha.encode('utf-8'), senha_hash.encode('utf-8')):
            token = jwt.encode(
                {
                    'id': user_id,
                    'email': email,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({'token': token})
    return jsonify({'erro': 'Credenciais inválidas'}), 401

# ------------------- TAREFAS: ADICIONAR ---------------------
@app.route('/tarefas', methods=['POST'])
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

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tarefas (usuario_id, data, texto, horario, deadline, concluida) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (user_id, data_tarefa, texto, horario, deadline, False)
    )
    conn.commit()
    task_id = cur.fetchone()[0]
    return jsonify({'id': task_id})

# ------------------- TAREFAS: LISTAR POR DATA ---------------------
@app.route('/tarefas', methods=['GET'])
def list_tasks():
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    data_tarefa = request.args.get('date')
    cur = conn.cursor()
    if data_tarefa:
        cur.execute("SELECT id, texto, horario, deadline, concluida FROM tarefas WHERE usuario_id = %s AND data = %s", (user_id, data_tarefa))
    else:
        cur.execute("SELECT id, texto, horario, deadline, concluida, data FROM tarefas WHERE usuario_id = %s", (user_id,))
    tasks = [
        {
            'id': row[0],
            'text': row[1],
            'time': str(row[2]),
            'deadline': str(row[3]),
            'completed': row[4]
        }
        for row in cur.fetchall()
    ]
    return jsonify(tasks)

# ------------------- TAREFAS: REMOVER ---------------------
@app.route('/tarefas/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    cur = conn.cursor()
    cur.execute("DELETE FROM tarefas WHERE id = %s AND usuario_id = %s", (task_id, user_id))
    conn.commit()
    return '', 204

# ------------------- TAREFAS: CONCLUIR/DESCONCLUIR ---------------------
@app.route('/tarefas/<int:task_id>/concluir', methods=['POST'])
def toggle_task(task_id):
    token = request.headers.get('Authorization')
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'erro': 'Usuário não autenticado'}), 401

    data = request.get_json()
    completed = data.get('completed', False)

    cur = conn.cursor()
    cur.execute("UPDATE tarefas SET concluida = %s WHERE id = %s AND usuario_id = %s", (completed, task_id, user_id))
    conn.commit()
    return '', 204

# (Opcional) Rota protegida de teste
@app.route('/tarefas_protegidas', methods=['GET'])
def tarefas_protegidas():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'erro': 'Token não enviado'}), 401
    try:
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'msg': 'Acesso permitido!'})
    except jwt.ExpiredSignatureError:
        return jsonify({'erro': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'erro': 'Token inválido'}), 401

if __name__ == "__main__":
    app.run(debug=True)
