from flask import Flask, render_template, redirect, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import sqlite3

# 连接数据库
def connect_db():
    db = sqlite3.connect('test.db')
    db.cursor().executescript(
        'CREATE TABLE IF NOT EXISTS comments '
        '(id INTEGER PRIMARY KEY, '
        'comment TEXT,'
        'author INTEGER);'
        'CREATE TABLE IF NOT EXISTS users ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'username TEXT UNIQUE NOT NULL,'
        'password_hash TEXT NOT NULL,'
        'created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);'
        'CREATE TABLE IF NOT EXISTS tokens ('
        'token TEXT PRIMARY KEY,'
        'user_id INTEGER NOT NULL,'
        'created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);'
    )
    db.commit()
    return db

def generate_token(id):
    token = secrets.token_urlsafe(32)
    db = connect_db()
    db.cursor().execute('INSERT INTO tokens (token, user_id) VALUES (?, ?)', (token, id))
    db.commit()
    return token

def escape_string(str):
    if str == None:
        return None
    out = ""
    for i in range(len(str)):
        if str[i] == '<':
           out += "&lt;"
        elif str[i] == '>':
           out += "&gt;"
        elif str[i] == '&':
           out += "&amp;"
        elif str[i] == '\'':
           out += "&apos;"
        elif str[i] == '\"':
           out += "&quot;"
        elif str[i] == ' ':
           out += "&nbsp;"
        else:
           out += str[i]
    return out

# 添加评论
def add_comment(comment, author):
    db = connect_db()
    db.cursor().execute('INSERT INTO comments (comment, author) '
                        'VALUES (?, ?)', (comment, author))
    db.commit()

# 得到评论
def get_comments(search_query=None):
    db = connect_db()
    results = []
    get_all_query = 'SELECT comment, author FROM comments'
    for (comment, author) in db.cursor().execute(get_all_query).fetchall():
        if search_query is None or search_query in comment:
            name = ""
            match = db.cursor().execute('SELECT username FROM users WHERE id = (?)', [author]).fetchall()
            if len(match) == 0:
                name = "匿名用户"
            else:
                name = match[0][0]
            results.append({"content": escape_string(comment), "from": escape_string(name)})
    return results

def get_user_by_token(token):
    db = connect_db()
    user_id = -1
    if token:
        match = db.cursor().execute('SELECT * FROM tokens WHERE token = \'' + token +'\'').fetchall()      # vulnerability 1
        if len(match) > 0:
            user_id = match[0][1]
    return user_id

def get_name_by_id(user_id):
    db = connect_db()
    name = None
    if user_id > 0:
        match = db.cursor().execute('SELECT username FROM users WHERE id = ?', [user_id]).fetchall()
        if len(match) > 0:
            name = match[0][0]
    return name

# 启动flask
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    token = request.cookies.get('token')
    user_id = get_user_by_token(token)
    username = get_name_by_id(user_id)
    
    if request.method == 'POST':
        add_comment(request.form['comment'], user_id)

    search_query = request.args.get('q')
    comments = get_comments(search_query)

    return render_template('index.html',
                           comments=comments,
                           search_query=escape_string(search_query),
                           user_id=user_id,
                           username=escape_string(username))

@app.route('/login', methods=['POST'])
def login():
    username=request.form['username']
    password=request.form['password']
    db = connect_db()
    match = db.cursor().execute('SELECT id, username, password_hash FROM users '
                                'WHERE username = \'' + username + '\'').fetchall()  # vulnerability 2
    if len(match) == 0:
        return render_template('fail.html', msg = '用户名不存在', title = '登录失败')
    else:
        info = match[0]
        if not check_password_hash(info[2], password):
            return render_template('fail.html', msg = '密码错误', title = '登录失败')
        response = make_response(redirect("/"))
        response.set_cookie("token", generate_token(info[0]))
        return response

@app.route('/register', methods=['POST'])
def register():
    username=request.form['username']
    password_hash=generate_password_hash(request.form['password'])
    db = connect_db()
    if len(db.cursor().execute('SELECT * FROM users WHERE username = ?', [username]).fetchall()) > 0:
        return render_template('fail.html', msg = '用户名已存在', title = '注册失败')
    cur = db.cursor();
    cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                        (username, password_hash))
    db.commit()
    id = cur.lastrowid
    response = make_response(redirect("/"))
    response.set_cookie("token", generate_token(id))
    return response

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    token = request.cookies.get('token')
    if token:
        db = connect_db()
        db.cursor().execute('DELETE FROM tokens WHERE token = ?', [token])
        db.commit()
    return redirect('/')