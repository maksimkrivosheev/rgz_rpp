from flask import Flask, render_template, redirect, url_for, request
from flask_login import current_user
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)


login_manager = LoginManager()
login_manager.login_view = 'login'  
login_manager.init_app(app)

def get_db_connection():
    conn = psycopg2.connect("dbname='rgz_rpp' user='postgres' host='localhost' password='postgres'")
    return conn
    
def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, 
            email VARCHAR(255) UNIQUE NOT NULL, 
            password VARCHAR(255) NOT NULL, 
            username TEXT NOT NULL 
        );
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id SERIAL PRIMARY KEY,
            amount FLOAT NOT NULL,
            category VARCHAR(100) NOT NULL,
            description VARCHAR(200),
            user_id INTEGER REFERENCES users(id)
        );
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            action_type VARCHAR(50) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            record_id INTEGER NOT NULL
        );
    ''')

    conn.commit()
    cursor.close()
    conn.close()

class User(UserMixin):
    def __init__(self, id, email, password, username):
        self.id = id
        self.email = email
        self.password = password
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    if user_data:
        return User(id=user_data[0], email=user_data[1], password=user_data[2], username=user_data[3])
    return 

@app.route('/')
@login_required
def index():
    return render_template('base.html')

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        data = request.form
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO expenses (amount, category, description, user_id) VALUES (%s, %s, %s, %s) RETURNING id",
                               (data['amount'], data['category'], data.get('description'), current_user.id))
                expense_id = cursor.fetchone()[0]
                conn.commit()
                log_audit(current_user.id, 'add', expense_id)
            except psycopg2.Error as e:
                print(f"Ошибка добавления расхода: {e}")
                return "Ошибка добавления расхода", 500
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
        return redirect(url_for('list_expenses'))
    return render_template('add_expense.html')

@app.route('/list')
@login_required
def list_expenses():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM expenses WHERE user_id = %s", (current_user.id,))
            expenses = cursor.fetchall()
            return render_template('list_expenses.html', expenses=[{'id': exp[0], 'amount': exp[1], 'category': exp[2], 'description': exp[3]} for exp in expenses])
        except psycopg2.Error as e:
            print(f"Ошибка вывода списка расходов: {e}")
            return "Ошибка вывода списка расходов", 500
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

def log_audit(user_id, action_type, record_id):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO audit_logs (user_id, action_type, record_id) VALUES (%s, %s, %s)",
                           (user_id, action_type, record_id))
            conn.commit()
        except psycopg2.Error as e:
            print(f"Ошибка логирования аудита: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

@app.route('/edit/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            if request.method == 'POST':
                amount = request.form['amount']
                category = request.form['category']
                description = request.form['description']
                cursor.execute("UPDATE expenses SET amount = %s, category = %s, description = %s WHERE id = %s AND user_id = %s",
                               (amount, category, description, expense_id, current_user.id))
                conn.commit()
                log_audit(current_user.id, 'update', expense_id)
                return redirect(url_for('list_expenses'))
            else:
                cursor.execute("SELECT * FROM expenses WHERE id = %s AND user_id = %s", (expense_id, current_user.id))
                expense = cursor.fetchone()
                if expense:
                    return render_template('edit_expense.html', expense={'id': expense[0], 'amount': expense[1], 'category': expense[2], 'description': expense[3]})
                else:
                    return "Запись не найдена", 404
        except psycopg2.Error as e:
            print(f"Ошибка редактирования записи: {e}")
            return "Ошибка редактирования записи", 500
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

@app.route('/delete/<int:expense_id>', methods=['POST', 'GET'])
@login_required
def delete_expense(expense_id):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM expenses WHERE id = %s AND user_id = %s", (expense_id, current_user.id))
            conn.commit()
            log_audit(current_user.id, 'delete', expense_id)
            return redirect(url_for('list_expenses'))
        except psycopg2.Error as e:
            print(f"Ошибка удаления записи: {e}")
            return "Ошибка удаления записи", 500
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT id, email, password, username FROM users WHERE email = %s", (email,))
                user_data = cursor.fetchone()
                if user_data:
                    user = User(id=user_data[0], email=user_data[1], password=user_data[2], username=user_data[3])
                    if check_password_hash(user.password, password):
                        login_user(user)
                        return redirect(url_for('list_expenses')) 
                    else:
                        return render_template('login.html', error="Неверный пароль")
                else:
                    return render_template('login.html', error="Пользователь не найден")
            except psycopg2.Error as e:
                print(f"Ошибка входа: {e}")
                return render_template('login.html', error="Ошибка базы данных")
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            conn.close()
            return render_template('signup.html', error="Пользователь уже существует")
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (email, password, username) VALUES (%s, %s, %s)', (email, hashed_password, name))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=False)
