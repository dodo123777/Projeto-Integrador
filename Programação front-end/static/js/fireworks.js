class Fireworks {
    constructor() {
        this.canvas = document.getElementById('fireworksCanvas');
        this.ctx = this.canvas.getContext('2d');
        this.init();
    }

    init() {
        this.resizeCanvas();
        window.addEventListener('resize', () => this.resizeCanvas());
    }

    resizeCanvas() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    createEffect() {
        let particles = [];
        for (let i = 0; i < 100; i++) {
            particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                color: `hsl(${Math.random() * 360}, 100%, 70%)`,
                size: Math.random() * 3,
                alpha: 1
            });
        }

        const renderParticles = () => {
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            particles.forEach(p => {
                this.ctx.beginPath();
                this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                this.ctx.fillStyle = p.color;
                this.ctx.globalAlpha = p.alpha;
                this.ctx.fill();
                p.alpha -= 0.02;
            });
            particles = particles.filter(p => p.alpha > 0);
            if (particles.length > 0) {
                requestAnimationFrame(renderParticles);
            }
        };
        renderParticles();
    }
}

const fireworks = new Fireworks();