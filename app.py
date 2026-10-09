import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'clave_secreta_para_sesiones_flask_vs_code'
DATABASE = 'database.db'

# --- Conexión y Gestión de Base de Datos ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la tabla de usuarios con perfil extendido y ejecuta auto-migración."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Crear tabla con nuevos campos si no existe
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    
    # Auto-migración: agrega columnas si el archivo database.db ya existía previamente
    existing_cols = [row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
    new_cols = {
        'full_name': 'TEXT',
        'email': 'TEXT',
        'phone': 'TEXT',
        'is_active': 'INTEGER NOT NULL DEFAULT 1',
        'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
        'last_login': 'DATETIME'
    }
    for col_name, col_type in new_cols.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")

    # Crear el usuario admin inicial por defecto si no existe
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        hashed_password = generate_password_hash('1234')
        cursor.execute('''
            INSERT INTO users (username, password, role, full_name, email, phone, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('admin', hashed_password, 'ADMINISTRADOR', 'Administrador Principal', 'admin@sistema.local', 'N/A', 1))
        print("[DB] Usuario admin creado por defecto (Usuario: admin | Clave: 1234)")
    
    conn.commit()
    conn.close()

# --- Decoradores de Seguridad ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión para acceder al sistema.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in allowed_roles:
                flash('No tienes permisos suficientes para realizar esta acción.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Rutas de Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            # Verificación de borrado lógico / estado de cuenta
            if user['is_active'] == 0:
                conn.close()
                flash('Esta cuenta se encuentra inactiva. Contacta al administrador.', 'danger')
                return render_template('login.html')

            # Registrar la fecha y hora de última conexión (last_login)
            conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            conn.commit()
            conn.close()

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name'] or user['username']
            session['role'] = user['role']
            flash(f'¡Bienvenido/a, {session["full_name"]}! Acceso concedido como {user["role"]}.', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

# --- Rutas CRUD de Usuarios ---

# LEER: Lista completa con perfiles y estados
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, full_name, email, phone, role, is_active, created_at, last_login 
        FROM users ORDER BY id ASC
    ''').fetchall()
    conn.close()
    return render_template('dashboard.html', users=users)

# CREAR: Registra perfil extendido
@app.route('/user/create', methods=['GET', 'POST'])
@login_required
@roles_required('ADMINISTRADOR', 'SUPERVISOR')
def create_user():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        is_active = int(request.form.get('is_active', 1))

        if not username or not password or not role:
            flash('Usuario, contraseña y rol son campos obligatorios.', 'warning')
            return render_template('user_form.html', action='Crear')

        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            conn.execute('''
                INSERT INTO users (username, password, role, full_name, email, phone, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, hashed_password, role, full_name, email, phone, is_active))
            conn.commit()
            flash(f'Usuario "{username}" registrado con éxito.', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe. Elige otro.', 'danger')
        finally:
            conn.close()

    return render_template('user_form.html', action='Crear', user=None)

# ACTUALIZAR: Modifica perfil y estado
@app.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('ADMINISTRADOR', 'SUPERVISOR')
def edit_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user:
        conn.close()
        flash('El usuario solicitado no existe.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_password = request.form['password'].strip()
        new_role = request.form['role']
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        
        # Solo ADMINISTRADOR puede cambiar el estado activo/inactivo
        if session['role'] == 'ADMINISTRADOR':
            is_active = int(request.form.get('is_active', user['is_active']))
        else:
            is_active = user['is_active']

        try:
            if new_password:
                hashed_pw = generate_password_hash(new_password)
                conn.execute('''
                    UPDATE users 
                    SET username = ?, password = ?, role = ?, full_name = ?, email = ?, phone = ?, is_active = ?
                    WHERE id = ?
                ''', (new_username, hashed_pw, new_role, full_name, email, phone, is_active, user_id))
            else:
                conn.execute('''
                    UPDATE users 
                    SET username = ?, role = ?, full_name = ?, email = ?, phone = ?, is_active = ?
                    WHERE id = ?
                ''', (new_username, new_role, full_name, email, phone, is_active, user_id))
            
            conn.commit()
            flash(f'Perfil del usuario ID #{user_id} actualizado.', 'success')
            
            # Actualizar datos de sesión si modifica su propio perfil
            if user_id == session['user_id']:
                session['username'] = new_username
                session['full_name'] = full_name or new_username
                session['role'] = new_role

            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya está en uso por otra cuenta.', 'danger')
        finally:
            conn.close()

    conn.close()
    return render_template('user_form.html', action='Editar', user=user)

# BORRADO LÓGICO / CAMBIO DE ESTADO: Exclusivo de ADMINISTRADOR
@app.route('/user/toggle_status/<int:user_id>', methods=['POST'])
@login_required
@roles_required('ADMINISTRADOR')
def toggle_user_status(user_id):
    if user_id == session['user_id']:
        flash('No puedes desactivar tu propia cuenta mientras mantienes la sesión activa.', 'warning')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    user = conn.execute('SELECT is_active, username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        new_status = 0 if user['is_active'] == 1 else 1
        conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        
        estado_txt = "activado" if new_status == 1 else "desactivado (Borrado Lógico)"
        flash(f'El usuario "{user["username"]}" ha sido {estado_txt}.', 'info')

    conn.close()
    return redirect(url_for('dashboard'))

# --- Inicialización del Servidor ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)