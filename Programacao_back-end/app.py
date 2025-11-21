from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from controllers.user_controller import user_bp
from controllers.task_controller import task_bp

app = Flask(__name__)

CORS(
    app,
    resources={r"/*": {"origins": "https://receba777.netlify.app"}},
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type", "Authorization"],
)

app.config.from_object(Config)

# Registrar blueprints (APIs)
app.register_blueprint(user_bp)
app.register_blueprint(task_bp)

# Rota raiz só pra health check / teste
@app.route("/")
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(debug=True)
