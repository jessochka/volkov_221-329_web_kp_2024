from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime, timezone, timedelta
import os

if not os.path.exists('uploads'):
    os.makedirs('uploads')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'mysecret'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    login = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    avatar = db.Column(db.String(150), nullable=True, default='default_avatar.png')
    tasks = db.relationship('Task', backref='user', lazy=True)
    assigned_tasks = db.relationship('Task', secondary='task_assigned', backref='assigned_users', lazy='subquery')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(100), nullable=False, default='Назначена')
    category = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.String(100), nullable=False, default='Средний')
    deadline = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    files = db.relationship('File', backref='task', lazy=True)

class TaskAssigned(db.Model):
    __tablename__ = 'task_assigned'
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)

def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    wrap.__name__ = f.__name__
    return wrap

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('main'))
    
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        remember = request.form.get('remember')
        user = User.query.filter_by(login=login).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = f"{user.first_name} {user.last_name}"
            resp = make_response(redirect(url_for('main')))
            if remember:
                expires = datetime.now() + timedelta(days=30)
                resp.set_cookie('user_id', str(user.id), expires=expires)
                resp.set_cookie('user_name', f"{user.first_name} {user.last_name}", expires=expires)
            return resp
        else:
            flash('Логин или пароль неверны', 'danger')
    
    return render_template('auth.html')

@app.route('/main')
@login_required
def main():
    user = User.query.get(session['user_id'])
    tasks = Task.query.filter(
        (Task.user_id == user.id) | 
        (Task.assigned_users.any(id=user.id))
    ).order_by(
        db.case([(Task.priority == 'Высокий', 1), 
                 (Task.priority == 'Средний', 2), 
                 (Task.priority == 'Низкий', 3)]), 
        Task.deadline
    ).all()
    return render_template('main.html', tasks=tasks, current_user=user)

@app.route('/task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    users = User.query.all()
    if request.method == 'POST':
        if 'delete' in request.form:
            for file in task.files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.session.delete(file)
            db.session.delete(task)
            db.session.commit()
            return redirect(url_for('main'))
        task.title = request.form.get('title')
        task.description = request.form.get('description')
        task.status = request.form.get('status')
        task.category = request.form.get('category')
        task.priority = request.form.get('priority')
        task.deadline = datetime.strptime(request.form.get('deadline'), '%Y-%m-%d')
        assigned_user_ids = request.form.getlist('assigned_users')
        task.assigned_users = [User.query.get(uid) for uid in assigned_user_ids if uid != str(task.user_id)]
        
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                new_file = File(filename=filename, task=task)
                db.session.add(new_file)
        
        db.session.commit()
        return redirect(url_for('task_detail', task_id=task.id))
    return render_template('task_detail.html', task=task, users=users, current_user_id=session['user_id'])

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    current_user_id = session['user_id']
    users = User.query.all()
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        status = request.form.get('status')
        category = request.form.get('category')
        priority = request.form.get('priority')
        deadline = request.form.get('deadline')
        user_id = current_user_id
        new_task = Task(title=title, description=description, status=status, category=category, priority=priority, deadline=datetime.strptime(deadline, '%Y-%m-%d'), user_id=user_id)
        assigned_user_ids = request.form.getlist('assigned_users')
        new_task.assigned_users = [User.query.get(uid) for uid in assigned_user_ids if uid != str(current_user_id)]
        
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                new_file = File(filename=filename, task=new_task)
                db.session.add(new_file)
        
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('main'))
    return render_template('create_task.html', users=users, current_user_id=current_user_id)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if 'change_avatar' in request.form and 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar.filename != '':
                filename = secure_filename(avatar.filename)
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(avatar_path), exist_ok=True)
                avatar.save(avatar_path)
                user.avatar = filename

        user.first_name = request.form.get('first_name', user.first_name)
        user.last_name = request.form.get('last_name', user.last_name)
        user.login = request.form.get('login', user.login)
        password = request.form.get('password')
        if password and password != '********':
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id')
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('user_id', '', expires=0)
    resp.set_cookie('user_name', '', expires=0)
    return resp

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
