from flask import Flask, render_template
from flask_cors import CORS
from config import Config
from controllers.user_controller import user_bp
from controllers.task_controller import task_bp

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# Registrar blueprints
app.register_blueprint(user_bp)
app.register_blueprint(task_bp)

# Rotas para servir as páginas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)