// Verificar se usuário está logado
function checkAuth() {
    if (!localStorage.getItem('token')) {
        window.location.href = '/login';
    }
}

// Fazer logout
function logout() {
    localStorage.removeItem('token');
    window.location.href = '/login';
}

// Executar verificação ao carregar
checkAuth();

// Adicionar evento ao botão de logout
document.addEventListener('DOMContentLoaded', () => {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.onclick = logout;
    }
});