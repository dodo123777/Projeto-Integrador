const API_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:5000'
    : 'https://projeto-integrador-uvxi.onrender.com';

class TaskManager {
    constructor() {
        this.token = localStorage.getItem('token');
        this.selectedDate = document.getElementById('selectedDate');
        this.taskInput = document.getElementById('taskInput');
        this.timeInput = document.getElementById('timeInput');
        this.deadlineInput = document.getElementById('deadlineInput');
        this.addTaskButton = document.getElementById('addTaskButton');
        this.taskList = document.getElementById('taskList');
        this.statusMessage = document.getElementById('statusMessage');
        this.focusToggle = document.getElementById('focusToggle');

        this.init();
    }

    init() {
        // Botão de adicionar tarefa
        this.addTaskButton.addEventListener('click', () => this.addTask());

        // Quando mudar a data, recarrega tarefas daquele dia
        this.selectedDate.addEventListener('change', () => {
            const date = this.selectedDate.value;
            if (date) this.renderTasks(date);
        });

        // Modo foco para reduzir distrações visuais
        if (this.focusToggle) {
            this.focusToggle.addEventListener('click', () => {
                document.body.classList.toggle('focus-mode');
                const focusEnabled = document.body.classList.contains('focus-mode');
                this.focusToggle.textContent = focusEnabled ? 'Sair do modo foco' : 'Modo foco';
                this.showStatus(focusEnabled ? 'Modo foco ativado. Apenas o essencial na tela.' : 'Modo padrão restaurado.');
            });
        }

        // Se já tiver uma data selecionada ao carregar, renderiza
        if (this.selectedDate.value) {
            this.renderTasks(this.selectedDate.value);
        }
    }

    async fetchTasks(date) {
        const resp = await fetch(`${API_URL}/tarefas?date=${encodeURIComponent(date)}`, {
            headers: {
                'Authorization': this.token
            }
        });
        return await resp.json();
    }

    async saveTask(task, date) {
        await fetch(`${API_URL}/tarefas`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': this.token
            },
            body: JSON.stringify({
                text: task.text,
                time: task.time,
                deadline: task.deadline,
                date: date
            })
        });
    }

    async removeTask(taskId) {
        await fetch(`${API_URL}/tarefas/${taskId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': this.token
            }
        });
    }

    async toggleComplete(taskId, completed) {
        await fetch(`${API_URL}/tarefas/${taskId}/concluir`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': this.token
            },
            body: JSON.stringify({ completed })
        });
    }

    async renderTasks(date) {
        const tasks = await this.fetchTasks(date);
        this.taskList.innerHTML = "";

        tasks.forEach((task) => {
            const li = document.createElement('li');

            li.innerHTML = `
                <div class="task-details">
                    <span>${task.text}</span>
                    <span class="time">Horário: ${task.time}</span>
                    <span class="time">Concluir até: ${task.deadline}</span>
                </div>
                <div class="task-actions">
                    <button class="delete-btn">Remover</button>
                    <button class="check-btn">${task.completed ? 'Desfazer' : 'Concluir'}</button>
                </div>
            `;

            li.classList.add('fade-in');

            const checkButton = li.querySelector('.check-btn');
            const deleteButton = li.querySelector('.delete-btn');

            checkButton.addEventListener('click', async () => {
                await this.toggleComplete(task.id, !task.completed);
                this.showStatus(!task.completed ? 'Bom trabalho! Você concluiu uma tarefa.' : 'Tarefa reaberta. Reorganize o foco.');
                this.renderTasks(date);
            });

            deleteButton.addEventListener('click', async () => {
                await this.removeTask(task.id);
                this.showStatus('Tarefa removida.', 'neutral');
                this.renderTasks(date);
            });

            if (task.completed) {
                li.classList.add('task-done');
                li.classList.add('pulse-success');
            }

            this.taskList.appendChild(li);
        });

        // Atualiza barra de progresso, se existir
        if (typeof progressManager !== 'undefined') {
            progressManager.update(tasks);
        }
    }

    async addTask() {
        const taskText = this.taskInput.value.trim();
        const taskTime = this.timeInput.value.trim();
        const taskDeadline = this.deadlineInput.value.trim();
        const date = this.selectedDate.value;

        if (!date || !taskText || !taskTime || !taskDeadline) {
            alert("Preencha todos os campos!");
            return;
        }

        // Validar formato HH:MM
        if (!/^\d{2}:\d{2}$/.test(taskTime) || !/^\d{2}:\d{2}$/.test(taskDeadline)) {
            alert("Digite os horários no formato correto, ex: 13:30");
            return;
        }

        const task = {
            text: taskText,
            time: taskTime,
            deadline: taskDeadline,
            completed: false
        };

        await this.saveTask(task, date);

        // Limpar campos
        this.taskInput.value = "";
        this.timeInput.value = "";
        this.deadlineInput.value = "";

        // Recarregar lista
        this.renderTasks(date);
        this.showStatus('Tarefa adicionada! Comece pelo primeiro passo.');
    }

    showStatus(message, tone = 'positive') {
        if (!this.statusMessage) return;
        const colors = {
            positive: '#0f7a8c',
            neutral: '#4a6072',
            warning: '#b52e46'
        };

        this.statusMessage.style.color = colors[tone] || colors.positive;
        this.statusMessage.textContent = message;
        this.statusMessage.classList.remove('hide');

        clearTimeout(this.statusTimeout);
        this.statusTimeout = setTimeout(() => {
            this.statusMessage.classList.add('hide');
        }, 3200);
    }
}

// Inicializa o gerenciador de tarefas quando a página estiver pronta
document.addEventListener('DOMContentLoaded', () => {
    new TaskManager();
});
