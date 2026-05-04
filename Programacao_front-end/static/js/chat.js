const API_URL = ['localhost', '127.0.0.1'].includes(window.location.hostname)
    ? 'http://localhost:5000'
    : 'https://projeto-integrador-uvxi.onrender.com';

class ChatManager {
    constructor() {
        this.chatForm = document.getElementById('chatForm');
        this.chatMessages = document.getElementById('chatMessages');
        this.messageInput = document.getElementById('messageInput');
        this.sendButton = document.getElementById('sendButton');
        this.statusText = document.getElementById('statusText');
        this.isSending = false;

        this.init();
    }

    init() {
        this.addMessage('assistant', 'Olá! Eu sou o chat da InfoHelp. Pode mandar sua pergunta.');

        this.chatForm.addEventListener('submit', (event) => {
            event.preventDefault();
            this.sendMessage();
        });

        this.messageInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                this.sendMessage();
            }
        });

        this.messageInput.addEventListener('input', () => this.autoResize());
        this.messageInput.focus();
        this.autoResize();
    }

    autoResize() {
        this.messageInput.style.height = 'auto';
        this.messageInput.style.height = `${Math.min(this.messageInput.scrollHeight, 140)}px`;
    }

    setStatus(text) {
        this.statusText.textContent = text;
    }

    addMessage(role, text) {
        const messageElement = document.createElement('article');
        messageElement.className = `message ${role}`;

        if (role === 'assistant') {
            messageElement.innerHTML = marked.parse(text);
        } else {
            messageElement.textContent = text;
        }

        this.chatMessages.appendChild(messageElement);
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    toggleSendingState(isSending) {
        this.isSending = isSending;
        this.sendButton.disabled = isSending;
        this.messageInput.disabled = isSending;
        this.sendButton.textContent = isSending ? 'Enviando...' : 'Enviar';
    }

    async sendMessage() {
        const message = this.messageInput.value.trim();
        const token = localStorage.getItem('token');

        if (!message || this.isSending) {
            return;
        }

        if (!token) {
            window.location.href = 'login.html';
            return;
        }

        this.addMessage('user', message);
        this.messageInput.value = '';
        this.autoResize();
        this.toggleSendingState(true);
        this.setStatus('Pensando...');

        try {
            const response = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': token
                },
                body: JSON.stringify({ message })
            });

            const data = await response.json().catch(() => ({}));

            if (response.status === 401) {
                localStorage.removeItem('token');
                window.location.href = 'login.html';
                return;
            }

            if (!response.ok) {
                throw new Error(data.erro || 'Erro ao conversar com a IA.');
            }

            this.addMessage('assistant', data.reply || 'A IA não retornou nenhuma resposta.');
            this.setStatus('');
        } catch (error) {
            console.error('Erro no chat:', error);
            this.addMessage('assistant', `Desculpe, ocorreu um problema: ${error.message}`);
            this.setStatus('Não foi possível concluir a resposta agora.');
        } finally {
            this.toggleSendingState(false);
            this.messageInput.focus();
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new ChatManager();
});
