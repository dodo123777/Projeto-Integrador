class ProgressManager {
    constructor() {
        this.progressBar = document.getElementById('progressBar');
        this.progressPerc = document.getElementById('progressPerc');
        this.congratsMessage = document.getElementById('congratsMessage');
    }

    update(tasks) {
        const completedTasks = tasks.filter(task => task.completed).length;
        const percentage = tasks.length > 0 ? Math.round((completedTasks / tasks.length) * 100) : 0;

        this.progressBar.style.width = `${percentage}%`;
        this.progressPerc.textContent = percentage > 0 ? `${percentage}%` : "";

        if (percentage === 100 && tasks.length > 0) {
            this.showCongrats();
        }
    }

    showCongrats() {
        this.congratsMessage.style.display = "block";
        fireworks.createEffect();
        setTimeout(() => {
            this.congratsMessage.style.display = "none";
        }, 5000);
    }
}

const progressManager = new ProgressManager();