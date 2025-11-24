class ProgressManager {
    constructor() {
        this.progressBar = document.getElementById('progressBar');
        this.progressPerc = document.getElementById('progressPerc');
        this.congratsMessage = document.getElementById('congratsMessage');
        this.progressCaption = document.getElementById('progressCaption');
    }

    update(tasks) {
        const completedTasks = tasks.filter(task => task.completed).length;
        const percentage = tasks.length > 0 ? Math.round((completedTasks / tasks.length) * 100) : 0;

        this.progressBar.style.width = `${percentage}%`;
        this.progressPerc.textContent = percentage > 0 ? `${percentage}%` : "";

        if (this.progressCaption) {
            if (percentage === 0) {
                this.progressCaption.textContent = 'Comece com algo de 5 minutos para ganhar impulso.';
            } else if (percentage < 50) {
                this.progressCaption.textContent = 'Bom início! Termine um bloco curto e volte para a lista.';
            } else if (percentage < 100) {
                this.progressCaption.textContent = 'Você está no meio do caminho. Respire e conclua o próximo passo.';
            } else {
                this.progressCaption.textContent = 'Dia concluído! Aproveite o descanso.';
            }
        }

        if (percentage === 100 && tasks.length > 0) {
            this.showCongrats();
        }
    }

    showCongrats() {
        if (document.body.classList.contains('focus-mode')) {
            return;
        }
        this.congratsMessage.style.display = "block";
        fireworks.createEffect();
        setTimeout(() => {
            this.congratsMessage.style.display = "none";
        }, 5000);
    }
}

const progressManager = new ProgressManager();