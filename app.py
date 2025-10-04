from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, Flask 后端已启动！'

if __name__ == '__main__':
    app.run(debug=True)