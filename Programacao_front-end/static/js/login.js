// URL da API (back-end no Render)
const API_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:5000'
    : 'https://projeto-integrador-uvxi.onrender.com';

class LoginManager {
    constructor() {
        this.baseURL = API_URL;
        this.init();
    }


    init() {
        // Elementos dos formulários
        this.loginForm = document.getElementById('loginForm');
        this.registerForm = document.getElementById('registerForm');
        this.resetForm = document.getElementById('resetForm');

        // Elementos de erro
        this.erroLogin = document.getElementById('erroLogin');
        this.erroRegistro = document.getElementById('erroRegistro');
        this.erroReset = document.getElementById('erroReset');

        // Adicionar event listeners
        this.addEventListeners();
        
        // Verificar se já está logado
        this.checkAlreadyLoggedIn();
    }

    addEventListeners() {
        // Botões principais
        document.getElementById('loginBtn').addEventListener('click', () => this.fazerLogin());
        document.getElementById('registerBtn').addEventListener('click', () => this.fazerRegistro());
        document.getElementById('resetBtn').addEventListener('click', () => this.fazerReset());

        // Botões de navegação
        document.getElementById('openRegisterBtn').addEventListener('click', () => this.abrirRegistro());
        document.getElementById('closeRegisterBtn').addEventListener('click', () => this.fecharRegistro());
        document.getElementById('openResetBtn').addEventListener('click', () => this.abrirReset());
        document.getElementById('closeResetBtn').addEventListener('click', () => this.fecharReset());

        // Enter para fazer login
        document.addEventListener('keydown', (e) => {
            if (e.key === "Enter" && this.loginForm.style.display !== "none") {
                this.fazerLogin();
            }
        });
    }

    checkAlreadyLoggedIn() {
        if (localStorage.getItem('token')) {
            window.location.href = 'index.html';
        }
    }

    // Navegação entre formulários
    abrirRegistro() {
        this.registerForm.style.display = 'flex';
        this.loginForm.style.display = 'none';
        this.limparErros();
    }

    fecharRegistro() {
        this.registerForm.style.display = 'none';
        this.loginForm.style.display = 'flex';
        this.limparErros();
        this.limparCamposRegistro();
    }

    abrirReset() {
        this.resetForm.style.display = 'flex';
        this.loginForm.style.display = 'none';
        this.limparErros();
    }

    fecharReset() {
        this.resetForm.style.display = 'none';
        this.loginForm.style.display = 'flex';
        this.limparErros();
        this.limparCamposReset();
    }

    limparErros() {
        this.erroLogin.innerText = "";
        this.erroRegistro.innerText = "";
        this.erroReset.innerText = "";
    }

    limparCamposRegistro() {
        document.getElementById('regNome').value = '';
        document.getElementById('regEmail').value = '';
        document.getElementById('regSenha').value = '';
    }

    limparCamposReset() {
        document.getElementById('resetEmail').value = '';
        document.getElementById('resetSenha').value = '';
    }

    // Validações
    validarEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    validarSenha(senha) {
        return senha.length >= 6;
    }

    // Operações de API
    async fazerLogin() {
        const email = document.getElementById('loginEmail').value.trim();
        const senha = document.getElementById('loginSenha').value;

        // Validações básicas
        if (!email || !senha) {
            this.erroLogin.innerText = "Preencha todos os campos!";
            return;
        }

        if (!this.validarEmail(email)) {
            this.erroLogin.innerText = "Email inválido!";
            return;
        }

        try {
            const response = await fetch(`${this.baseURL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, senha })
            });

            const data = await response.json();

            if (data.token) {
                localStorage.setItem('token', data.token);
                window.location.href = "index.html";
            } else {
                this.erroLogin.innerText = data.erro || 'Erro no login';
            }
        } catch (error) {
            console.error('Erro ao fazer login:', error);
            this.erroLogin.innerText = 'Erro ao conectar ao servidor!';
        }
    }

    async fazerRegistro() {
        const nome = document.getElementById('regNome').value.trim();
        const email = document.getElementById('regEmail').value.trim();
        const senha = document.getElementById('regSenha').value;

        // Validações
        if (!nome || !email || !senha) {
            this.erroRegistro.innerText = "Preencha todos os campos!";
            return;
        }

        if (!this.validarEmail(email)) {
            this.erroRegistro.innerText = "Email inválido!";
            return;
        }

        if (!this.validarSenha(senha)) {
            this.erroRegistro.innerText = "A senha deve ter pelo menos 6 caracteres!";
            return;
        }

        try {
            const response = await fetch(`${this.baseURL}/registrar`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ nome, email, senha })
            });

            const data = await response.json();

            if (data.msg) {
                alert(data.msg + " Agora faça login.");
                this.fecharRegistro();
                // Preencher email no login
                document.getElementById('loginEmail').value = email;
            } else {
                this.erroRegistro.innerText = data.erro || 'Erro ao registrar';
            }
        } catch (error) {
            console.error('Erro ao registrar:', error);
            this.erroRegistro.innerText = 'Erro ao conectar ao servidor!';
        }
    }

    async fazerReset() {
        const email = document.getElementById('resetEmail').value.trim();
        const nova_senha = document.getElementById('resetSenha').value;

        // Validações
        if (!email || !nova_senha) {
            this.erroReset.innerText = "Preencha todos os campos!";
            return;
        }

        if (!this.validarEmail(email)) {
            this.erroReset.innerText = "Email inválido!";
            return;
        }

        if (!this.validarSenha(nova_senha)) {
            this.erroReset.innerText = "A senha deve ter pelo menos 6 caracteres!";
            return;
        }

        try {
            const response = await fetch(`${this.baseURL}/esqueci_senha`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, nova_senha })
            });

            const data = await response.json();

            if (data.msg) {
                alert(data.msg + " Agora faça login.");
                this.fecharReset();
                // Preencher email no login
                document.getElementById('loginEmail').value = email;
            } else {
                this.erroReset.innerText = data.erro || 'Erro ao redefinir';
            }
        } catch (error) {
            console.error('Erro ao redefinir senha:', error);
            this.erroReset.innerText = 'Erro ao conectar ao servidor!';
        }
    }
}

// Inicializar quando a página carregar
document.addEventListener('DOMContentLoaded', () => {
    new LoginManager();
});