from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename #10/30
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"  # 正式部署时改为环境变量！

# -----------------------
# 数据库配置
# -----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# -----------------------
# 上传配置 10/30
# -----------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "doc", "docx", "xls", "xlsx"}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

# -----------------------
# 模型
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    upload = db.relationship('Upload', uselist=False, backref='user', cascade='all, delete-orphan')

    def get_id(self):
        return str(self.id)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    saved_path = db.Column(db.String(512), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

# -----------------------
# Flask-Login 设置
# -----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # 未登录用户访问受保护页面时重定向到 login

@login_manager.user_loader
def load_user(user_id):
    """从存储中加载用户对象"""
    return User.query.get(int(user_id))

# -----------------------
# 路由
# -----------------------

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username, is_admin=current_user.is_admin)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)  # ✅ 登录并保存到 session
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        exists = User.query.filter_by(username=username).first()
        if exists:
            flash('Username already exists!')
        else:
            user = User(username=username, password_hash=generate_password_hash(password), is_admin=False)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/upload', methods=['GET', 'POST'])# 10/30
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('未找到文件字段。')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('未选择文件。')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_prefix = f"u{current_user.id}_"
            final_name = user_prefix + filename
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], final_name)

            # 如果已有文件记录，先删除旧文件并记录
            if current_user.upload:
                try:
                    if os.path.exists(current_user.upload.saved_path):
                        os.remove(current_user.upload.saved_path)
                except Exception:
                    pass
                db.session.delete(current_user.upload)
                db.session.commit()

            file.save(save_path)
            record = Upload(filename=final_name, saved_path=save_path, user_id=current_user.id)
            db.session.add(record)
            db.session.commit()
            flash(f'上传成功：{filename}')
            return redirect(url_for('uploaded_file', filename=final_name))
        else:
            flash('文件类型不被允许。')
            return redirect(request.url)
    return render_template('upload.html')

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# -----------------------
# 管理员后台
# -----------------------
@app.route('/admin')
@login_required
def admin_index():
    if not current_user.is_admin:
        flash('需要管理员权限。')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.post('/admin/user/<int:user_id>/delete_file')
@login_required
def admin_delete_file(user_id):
    if not current_user.is_admin:
        flash('需要管理员权限。')
        return redirect(url_for('admin_index'))
    user = User.query.get_or_404(user_id)
    if user.upload:
        try:
            if os.path.exists(user.upload.saved_path):
                os.remove(user.upload.saved_path)
        except Exception:
            pass
        db.session.delete(user.upload)
        db.session.commit()
        flash('已删除该用户的文件。')
    return redirect(url_for('admin_index'))

@app.post('/admin/user/<int:user_id>/delete')
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('需要管理员权限。')
        return redirect(url_for('admin_index'))
    user = User.query.get_or_404(user_id)
    if user.upload:
        try:
            if os.path.exists(user.upload.saved_path):
                os.remove(user.upload.saved_path)
        except Exception:
            pass
    if user.id == current_user.id:
        flash('不能删除当前已登录管理员。')
        return redirect(url_for('admin_index'))
    db.session.delete(user)
    db.session.commit()
    flash('已删除用户。')
    return redirect(url_for('admin_index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()  # ✅ 清除用户登录状态
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password_hash=generate_password_hash('admin'), is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)
