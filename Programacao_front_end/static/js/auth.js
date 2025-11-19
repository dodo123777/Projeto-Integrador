// Verificar se usuário está logado
function checkAuth() {
    if (!localStorage.getItem('token')) {
        window.location.href = 'login.html';
    }
}

// Fazer logout
function logout() {
    localStorage.removeItem('token');
    window.location.href = 'login.html';
}

// Executar verificação ao carregar
document.addEventListener('DOMContentLoaded', () => {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    // Só checa auth se não estiver na página de login
    if (!window.location.pathname.endsWith('login.html')) {
        checkAuth();
    }
});
