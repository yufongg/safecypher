from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from neo4j import GraphDatabase
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Neo4j connection setup
uri = "bolt://neo4j:7687"
neo4j_user = "neo4j"
neo4j_password = "hellohello" 
driver = GraphDatabase.driver(uri, auth=(neo4j_user, neo4j_password))

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    with driver.session() as session:
        result = session.run("MATCH (u:User {username: $username}) RETURN u.username AS username", 
                             username=user_id)
        user = result.single()
        if user:
            return User(user_id)
    return None


def get_keyboards():
    with driver.session() as session:
        result = session.run("MATCH (k:Keyboard) RETURN k.name AS name, k.description AS description")
        return [{"name": row["name"], "description": row["description"]} for row in result]

def get_keyboard_by_name1(name):
    """
    Injection character '
    """
    with driver.session() as session:
        result = session.run("MATCH (k:Keyboard) WHERE k.name = '" + name + "' RETURN k.name AS name, k.description AS description")
        return [{"name": row["name"], "description": row["description"]} for row in result]

def get_keyboard_by_name2(name):
    """
    Injection character "
    """
    with driver.session() as session:
        result = session.run('MATCH (k:Keyboard) WHERE k.name = "' + name + '" RETURN k.name AS name, k.description AS description')
        return [{"name": row["name"], "description": row["description"]} for row in result]


def get_keyboard_by_name3(name):
    """
    Injection character <number>
    """
    with driver.session() as session:
        result = session.run("MATCH (k:Keyboard) WHERE id(k) = " + name + " RETURN k.name AS name, k.description AS description")
        return [{"name": row["name"], "description": row["description"]} for row in result]


def get_keyboard_by_name4(name):
    """
    Injection character '})
    """
    with driver.session() as session:
        result = session.run("MATCH (k:Keyboard {name: '" + name + "'}) RETURN k.name AS name, k.description AS description")
        return [{"name": row["name"], "description": row["description"]} for row in result]



def get_keyboard_by_name5(name):
    """
    Injection character "})
    """
    with driver.session() as session:
        result = session.run('MATCH (k:Keyboard {name: "' + name + '"}) RETURN k.name AS name, k.description AS description')
        return [{"name": row["name"], "description": row["description"]} for row in result]




@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # In production, use a hashed password
        with driver.session() as session:
            result = session.run("MATCH (u:User) WHERE u.username = $username AND u.password = $password RETURN u",
                                 username=username, password=password)
            user = result.single()
            if user:
                user_obj = User(username)
                login_user(user_obj)
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password')
    return render_template('login.html')

@app.route('/query')
@login_required
def query():
    keyboards = get_keyboards()
    return render_template('query.html', keyboards=keyboards)

@app.route('/search1', methods=['POST', 'GET'])
@login_required
def search1():
    if request.method == 'POST':
        keyboard_name = request.form['keyboard_name']
    else:  # Handling for GET request
        keyboard_name = request.args.get('keyboard_name', '')
    keyboard = get_keyboard_by_name1(keyboard_name)
    return render_template('query.html', keyboards=keyboard, search_type='search1')

@app.route('/search2', methods=['POST', 'GET'])
@login_required
def search2():
    if request.method == 'POST':
        keyboard_name = request.form['keyboard_name']
    else:  # Handling for GET request
        keyboard_name = request.args.get('keyboard_name', '')
    keyboard = get_keyboard_by_name2(keyboard_name)
    return render_template('query.html', keyboards=keyboard, search_type='search2')

@app.route('/search3', methods=['POST', 'GET'])
@login_required
def search3():
    if request.method == 'POST':
        keyboard_name = request.form['keyboard_name']
    else:  # Handling for GET request
        keyboard_name = request.args.get('keyboard_name', '')
    keyboard = get_keyboard_by_name3(keyboard_name)
    return render_template('query.html', keyboards=keyboard, search_type='search3')

@app.route('/search4', methods=['POST', 'GET'])
@login_required
def search4():
    if request.method == 'POST':
        keyboard_name = request.form['keyboard_name']
    else:  # Handling for GET request
        keyboard_name = request.args.get('keyboard_name', '')
    keyboard = get_keyboard_by_name4(keyboard_name)
    return render_template('query.html', keyboards=keyboard, search_type='search4')

@app.route('/search5', methods=['POST', 'GET'])
@login_required
def search5():
    if request.method == 'POST':
        keyboard_name = request.form['keyboard_name']
    else:  # Handling for GET request
        keyboard_name = request.args.get('keyboard_name', '')
    keyboard = get_keyboard_by_name5(keyboard_name)
    return render_template('query.html', keyboards=keyboard, search_type='search5')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True, port=3333)
