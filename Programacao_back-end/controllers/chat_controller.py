from flask import Blueprint, jsonify, request
import requests  # biblioteca HTTP para chamar a API do Gemini

from auth import auth_required  # decorator que valida o JWT antes de entrar na rota
from config import Config       # lê GEMINI_API_KEY e GEMINI_MODEL do .env / Render


# Blueprint registrado em app.py como chat_bp
chat_bp = Blueprint("chat", __name__)

# URL base da API — {model} é substituído pelo valor de GEMINI_MODEL em runtime
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def extract_reply(response_data):
    """Navega no JSON da Gemini e devolve o texto da resposta, ou None se não achar."""
    candidates = response_data.get("candidates") or []

    for candidate in candidates:
        content = candidate.get("content") or {}
        parts = content.get("parts") or []
        # filtra só as parts que têm texto (ignora parts de thinking quando includeThoughts=True)
        texts = [part.get("text", "").strip() for part in parts if part.get("text")]

        if texts:
            return "\n".join(texts)

    return None


def extract_error_message(response_data):
    """Tenta extrair uma mensagem de erro legível do JSON da Gemini."""
    error = response_data.get("error") or {}
    if error.get("message"):
        return error["message"]

    # promptFeedback aparece quando a API bloqueia a mensagem por segurança
    prompt_feedback = response_data.get("promptFeedback") or {}
    block_reason = prompt_feedback.get("blockReason")
    if block_reason:
        return f"A solicitação foi bloqueada pela API ({block_reason})."

    return None


# POST /chat — protegida por JWT (auth_required rejeita sem token válido → 401)
@chat_bp.route("/chat", methods=["POST"])
@auth_required
def chat():
    # Segurança: garante que as variáveis de ambiente estão presentes antes de prosseguir
    if not Config.GEMINI_API_KEY:
        return jsonify({"erro": "GEMINI_API_KEY não configurada no servidor."}), 500

    if not Config.GEMINI_MODEL:
        return jsonify({"erro": "GEMINI_MODEL não configurado no servidor."}), 500

    # Lê o JSON do body; silent=True evita crash se o body não for JSON válido
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"erro": "Envie uma mensagem para o chat."}), 400

    payload = {
        # systemInstruction: contexto fixo enviado em toda requisição — define
        # personalidade, regras e tom do assistente ANTES da mensagem do usuário.
        # Altere aqui para mudar o comportamento geral do chat.
        "systemInstruction": {
            "parts": [
                {
                    "text": (
                        "Você é um assistente virtual especializado em organização e produtividade, "
                        "projetado exclusivamente para apoiar pessoas com TDAH (Transtorno de Déficit de Atenção "
                        "com Hiperatividade) e Autismo.\n\n"
                        "Seu objetivo é ser um facilitador de rotina: tirar dúvidas sobre métodos de foco, "
                        "ajudar a quebrar tarefas complexas em passos menores e explicar técnicas de produtividade "
                        "de forma simples.\n\n"
                        "Siga estas REGRAS INQUEBRÁVEIS de comportamento e segurança:\n\n"
                        "1. A BARREIRA CLÍNICA (MÉDICA):\n"
                        "- Você NÃO é um profissional de saúde, psicólogo, psiquiatra ou médico.\n"
                        "- Você é terminantemente proibido de fornecer diagnósticos, sugerir tratamentos, "
                        "validar sintomas ou recomendar qualquer tipo de medicação (como Ritalina, Venvanse, etc.).\n"
                        "- Se o usuário relatar crises (meltdown, burnout, ansiedade forte) ou pedir conselhos "
                        "médicos, PARE a geração de dicas imediatamente e responda com empatia, mas seja firme: "
                        "'Percebo que você está passando por um momento difícil, mas como sou uma inteligência "
                        "artificial de organização, não posso dar orientações de saúde. Por favor, procure seu "
                        "médico ou terapeuta para conversar sobre isso de forma segura.'\n\n"
                        "2. O LIMITE DA TELEMETRIA (DADOS REAIS):\n"
                        "- Atualmente, você é 'cego' para os dados reais do usuário. Você NÃO tem acesso ao "
                        "banco de dados, ao calendário, aos horários ou à lista de tarefas da pessoa.\n"
                        "- Se o usuário disser 'o que eu tenho para fazer hoje?' ou 'coloque uma reunião amanhã', "
                        "responda educadamente explicando essa limitação: 'Ainda não tenho os cabos conectados à "
                        "sua agenda real! Por enquanto, só consigo te dar dicas gerais e tirar dúvidas, mas não "
                        "consigo ler ou alterar seus compromissos. Essa função chegará em breve.'\n\n"
                        "3. O SEU TOM DE VOZ E FORMATO DE RESPOSTA:\n"
                        "- Seja extremamente claro, literal e objetivo. Evite sarcasmo, ironia ou metáforas "
                        "complexas que possam ser interpretadas de forma literal por usuários no espectro autista.\n"
                        "- Seja acolhedor e paciente, nunca faça o usuário se sentir culpado por não conseguir "
                        "focar ou por esquecer algo.\n"
                        "- NUNCA envie 'paredões de texto'. Use formatação em tópicos (bullet points), negrito "
                        "para destacar palavras-chave e parágrafos curtos. O cérebro com TDAH precisa de "
                        "informações 'escaneáveis' e visuais.\n\n"
                        "4. COMO VOCÊ DEVE AJUDAR:\n"
                        "- Ensine ativamente técnicas de gestão de tempo, como a Técnica Pomodoro (com tempos "
                        "adaptados), o Time Blocking (Bloqueio de Tempo) e a Regra dos 2 Minutos.\n"
                        "- Se o usuário apresentar uma tarefa grande (ex: 'preciso arrumar meu quarto'), "
                        "quebre-a em passos minúsculos, quase ridículos de tão fáceis, para evitar a paralisia "
                        "de análise."
                    )
                }
            ]
        },

        # contents: histórico da conversa — por agora só a mensagem atual do usuário.
        # Para adicionar memória de conversa no futuro, empilhe mensagens anteriores aqui.
        "contents": [
            {
                "role": "user",
                "parts": [{"text": message}],
            }
        ],

        "generationConfig": {
            # temperature: controla criatividade. 0 = mais preciso, 1 = mais criativo.
            "temperature": 0.7,

            # maxOutputTokens: limite de tokens na resposta. ~1024 ≈ ~750 palavras.
            "maxOutputTokens": 1024,

            "thinkingConfig": {
                # thinkingBudget: tokens reservados para raciocínio interno antes de responder.
                # 0 = desativado | 512–1024 = leve/médio | 2048+ = profundo | -1 = automático
                "thinkingBudget": 1024,

                # includeThoughts: True expõe o raciocínio na resposta (útil para debug).
                # Manter False em produção — o usuário só vê a resposta final.
                "includeThoughts": False,
            },
        },
    }

    try:
        # A chave da API vai como query param (?key=...), não no header
        response = requests.post(
            GEMINI_API_URL.format(model=Config.GEMINI_MODEL),
            params={"key": Config.GEMINI_API_KEY},
            json=payload,
            timeout=30,  # segundos — evita o request ficar pendurado para sempre
        )
        response_data = response.json()
    except requests.Timeout:
        return jsonify({"erro": "A IA demorou demais para responder. Tente novamente."}), 504
    except requests.RequestException:
        return jsonify({"erro": "Não foi possível se conectar à API da IA."}), 502
    except ValueError:
        # response.json() lança ValueError se o body não for JSON válido
        return jsonify({"erro": "A API da IA retornou uma resposta inválida."}), 502

    error_message = extract_error_message(response_data)
    if not response.ok:
        return jsonify({"erro": error_message or "Falha ao obter resposta da IA."}), 502

    reply = extract_reply(response_data)
    if not reply:
        return jsonify({"erro": error_message or "A IA não retornou uma resposta em texto."}), 502

    # Devolve só o texto final para o front-end
    return jsonify({"reply": reply}), 200