from database import db_manager

class TaskModel:
    def __init__(self):
        self.db = db_manager

    def add_task(self, user_id, texto, data_tarefa, horario, deadline):
        cur = self.db.get_cursor()
        try:
            cur.execute(
                "INSERT INTO tarefas (usuario_id, data, texto, horario, deadline, concluida) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (user_id, data_tarefa, texto, horario, deadline, False)
            )
            task_id = cur.fetchone()[0]
            self.db.commit()
            return task_id
        except Exception as e:
            print(f"[task_model.py] Erro ao adicionar tarefa: {e}")
            self.db.rollback()
            raise e

    def list_tasks(self, user_id, data_tarefa=None):
        cur = self.db.get_cursor()
        if data_tarefa:
            cur.execute("SELECT id, texto, horario, deadline, concluida FROM tarefas WHERE usuario_id = %s AND data = %s", 
                       (user_id, data_tarefa))
        else:
            cur.execute("SELECT id, texto, horario, deadline, concluida, data FROM tarefas WHERE usuario_id = %s", 
                       (user_id,))
        
        tasks = []
        for row in cur.fetchall():
            task = {
                'id': row[0],
                'text': row[1],
                'time': str(row[2]),
                'deadline': str(row[3]),
                'completed': row[4]
            }
            tasks.append(task)
        return tasks

    def delete_task(self, task_id, user_id):
        cur = self.db.get_cursor()
        cur.execute("DELETE FROM tarefas WHERE id = %s AND usuario_id = %s", (task_id, user_id))
        self.db.commit()
        return cur.rowcount > 0

    def toggle_task(self, task_id, user_id, completed):
        cur = self.db.get_cursor()
        cur.execute("UPDATE tarefas SET concluida = %s WHERE id = %s AND usuario_id = %s", 
                   (completed, task_id, user_id))
        self.db.commit()
        return cur.rowcount > 0