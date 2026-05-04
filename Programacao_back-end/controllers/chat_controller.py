from flask import Blueprint, jsonify, request
import requests

from auth import auth_required
from config import Config


chat_bp = Blueprint("chat", __name__)

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def extract_reply(response_data):
    candidates = response_data.get("candidates") or []

    for candidate in candidates:
        content = candidate.get("content") or {}
        parts = content.get("parts") or []
        texts = [part.get("text", "").strip() for part in parts if part.get("text")]

        if texts:
            return "\n".join(texts)

    return None


def extract_error_message(response_data):
    error = response_data.get("error") or {}
    if error.get("message"):
        return error["message"]

    prompt_feedback = response_data.get("promptFeedback") or {}
    block_reason = prompt_feedback.get("blockReason")
    if block_reason:
        return f"A solicitação foi bloqueada pela API ({block_reason})."

    return None


@chat_bp.route("/chat", methods=["POST"])
@auth_required
def chat():
    if not Config.GEMINI_API_KEY:
        return jsonify({"erro": "GEMINI_API_KEY não configurada no servidor."}), 500

    if not Config.GEMINI_MODEL:
        return jsonify({"erro": "GEMINI_MODEL não configurado no servidor."}), 500

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"erro": "Envie uma mensagem para o chat."}), 400

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": message}],
            }
        ],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 512,
        },
    }

    try:
        response = requests.post(
            GEMINI_API_URL.format(model=Config.GEMINI_MODEL),
            params={"key": Config.GEMINI_API_KEY},
            json=payload,
            timeout=30,
        )
        response_data = response.json()
    except requests.Timeout:
        return jsonify({"erro": "A IA demorou demais para responder. Tente novamente."}), 504
    except requests.RequestException:
        return jsonify({"erro": "Não foi possível se conectar à API da IA."}), 502
    except ValueError:
        return jsonify({"erro": "A API da IA retornou uma resposta inválida."}), 502

    error_message = extract_error_message(response_data)
    if not response.ok:
        return jsonify({"erro": error_message or "Falha ao obter resposta da IA."}), 502

    reply = extract_reply(response_data)
    if not reply:
        return jsonify({"erro": error_message or "A IA não retornou uma resposta em texto."}), 502

    return jsonify({"reply": reply}), 200
