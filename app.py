from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"  # 正式部署时改为环境变量！

# -----------------------
# 模拟数据库
# -----------------------
users = {}  # username -> password_hash

# -----------------------
# Flask-Login 设置
# -----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # 未登录用户访问受保护页面时重定向到 login

# -----------------------
# 用户类
# -----------------------
class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login 默认用 .id 区分用户

@login_manager.user_loader
def load_user(user_id):
    """从存储中加载用户对象"""
    if user_id in users:
        return User(user_id)
    return None

# -----------------------
# 路由
# -----------------------

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_password_hash = users.get(username)
        if user_password_hash and check_password_hash(user_password_hash, password):
            user = User(username)
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

        if username in users:
            flash('Username already exists!')
        else:
            users[username] = generate_password_hash(password)
            flash('Registration successful! Please log in.')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  # ✅ 清除用户登录状态
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
