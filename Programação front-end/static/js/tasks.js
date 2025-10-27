class TaskManager {
    constructor() {
        this.token = localStorage.getItem('token');
        this.selectedDate = document.getElementById('selectedDate');
        this.taskInput = document.getElementById('taskInput');
        this.timeInput = document.getElementById('timeInput');
        this.deadlineInput = document.getElementById('deadlineInput');
        this.addTaskButton = document.getElementById('addTaskButton');
        this.taskList = document.getElementById('taskList');
        
        this.init();
    }

    init() {
        this.addTaskButton.addEventListener('click', () => this.addTask());
        this.selectedDate.addEventListener('change', () => {
            const date = this.selectedDate.value;
            if (date) this.renderTasks(date);
        });

        // Renderizar tarefas se data já estiver selecionada
        window.onload = () => {
            if (this.selectedDate.value) {
                this.renderTasks(this.selectedDate.value);
            }
        };
    }

    async fetchTasks(date) {
        const resp = await fetch(`http://localhost:5000/tarefas?date=${date}`, {
            headers: { 'Authorization': this.token }
        });
        return await resp.json();
    }

    async saveTask(task, date) {
        await fetch('http://localhost:5000/tarefas', {
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
        await fetch(`http://localhost:5000/tarefas/${taskId}`, {
            method: 'DELETE',
            headers: { 'Authorization': this.token }
        });
    }

    async toggleComplete(taskId, completed) {
        await fetch(`http://localhost:5000/tarefas/${taskId}/concluir`, {
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

            const checkButton = li.querySelector('.check-btn');
            const deleteButton = li.querySelector('.delete-btn');

            checkButton.addEventListener('click', async () => {
                await this.toggleComplete(task.id, !task.completed);
                this.renderTasks(date);
            });

            deleteButton.addEventListener('click', async () => {
                await this.removeTask(task.id);
                this.renderTasks(date);
            });

            if(task.completed){
                li.style.background = "#e3fbe5";
                li.style.opacity = "0.7";
                li.querySelectorAll(".task-details span")[0].style.textDecoration = "line-through";
            }

            this.taskList.appendChild(li);
        });

        progressManager.update(tasks);
    }

    async addTask() {
        const taskText = this.taskInput.value.trim();
        let taskTime = this.timeInput.value.trim();
        let taskDeadline = this.deadlineInput.value.trim();
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

        this.taskInput.value = "";
        this.timeInput.value = "";
        this.deadlineInput.value = "";

        this.renderTasks(date);
    }
}

const taskManager = new TaskManager();