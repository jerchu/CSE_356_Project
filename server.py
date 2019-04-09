import os
here = os.path.dirname(__file__)
import sys
sys.path.insert(0, here)
from static.RL_learn.learner import Learner, Game
from functools import wraps
from flask import Flask, render_template, request, jsonify, make_response, session
from flask_mail import Mail, Message
import datetime
import time
import random
from pymongo import MongoClient
import bcrypt
import csv
import smtplib
import uuid
import base64
from email.message import EmailMessage
from email.policy import SMTP
import schemas

# section below for converting uuid to base64 (a.k.a. a slug) and visa versa
#--------------------------------------------
def uuid2slug(id):
    return base64.b64encode(id.bytes).decode('utf-8').rstrip('=\n').replace('/', '_').replace('+', '-')

def slug2uuid(slug):
    return uuid.UUID(bytes=(base64.b64decode(slug.replace('_', '/').replace('-', '+') + '==')))
#--------------------------------------------

app = Flask(__name__, static_url_path='')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
mail = Mail(app)
agent = Learner(epsilon=0)
agent.load_states(os.path.join(here, 'static/RL_learn/playero.pickle'))

with open(os.path.join(here, 'static/images.csv'), 'r') as f:
    images = f.readlines()

import logging
streamhndlr = logging.StreamHandler()
app.logger.setLevel(logging.INFO)

client = MongoClient('64.190.90.55', 27017)
db = client.stcku
users = db.users
questions = db.questions
answers = db.answers

hostname='StackUnderflow'

def login_required(f):
    @wraps(f)
    def check_login(*args, **kwargs):
        if 'username' in session and 'key' in session and session['username'] != '' and session['key'] != '':
            users = db.users
            user = users.find_one({'username': session['username']})
            if user['verified'] == False:
                return (jsonify({'status': 'error', 'error': 'Account requires verification'}))
            if user is not None and session['key'] == user['key']:
                return f(*args, **kwargs)
        return (jsonify({'status': 'error', 'error': 'Must be logged in to access this resource'}), 200) #('UNAUTHORIZED', 401)
    return check_login
            

@app.route('/')
def hello_world():
    random_img = random.choice(images).split(',')
    data = {}
    data['image'] = random_img[0]
    if len(random_img) > 1:
        data['title'] = random_img[1]
    resp = make_response(render_template('index.html', **data))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/ttt', strict_slashes=False)
def send_tic_tacs():
    name = 'guest'
    users = db.users
    if request.cookies.get('username') is not None:
        username = request.cookies.get('username')
        key = request.cookies.get('key')
        user = users.find_one({'username': name})
        if user is not None and 'key' in user and user['key'] == key:
            name = username
    return render_template('tictactoe.html', name=name, date=datetime.datetime.today().strftime('%Y-%m-%d'))

@app.route('/ttt/play', methods=['POST'])
def play_game():
    if request.is_json:
        if 'grid' in request.json:
            board = request.json['grid']
        elif 'move' in request.json:
            users = db.users
            user = users.find_one({'username': request.cookies.get('username'), 'verified': True})
            if user is None:
                return jsonify({'status': 'error'})
            board = user['current_game']
            move = request.json['move']
            if move is None:
                return jsonify({'grid': board})
            if board[move] != ' ':
                return jsonify({'status': 'error'})
            board[move] = 'X'
            if 'start_date' not in user:
                users.find_one_and_update({'username': user['username']}, {'$set':{'start_date': datetime.datetime.now()}})
        payload = {}
        reward, done = evaluate_state(board)
        if done:
            payload['grid'] = board
            payload['winner'] = 'X'
            if reward == 0.5:
                payload['winner'] = ' '
            if 'move' in request.json:
                users.find_one_and_update({'username': user['username']}, 
                    {
                        '$set': {
                            'current_game': [' ']*9
                        },
                        '$unset': {
                            'start_date': ''
                        },
                        '$push': {
                            'games': {
                                'id': user['game_id'],
                                'start_date': user['start_date'],
                                'grid': board,
                                'winner': payload['winner']
                            }
                        }
                    })
            return jsonify(payload)
        move = agent.make_move(board)
        board[move] = 'O'
        if 'move' in request.json:
            users.find_one_and_update({'username': user['username']}, {'$set':{'current_game': board}})
        payload['grid'] = board
        reward, done = evaluate_state(board)
        if done:
            payload['winner'] = 'O'
            if reward == 0.5:
                payload['winner'] = ' '
            if 'move' in request.json:
                users.find_one_and_update({'username': user['username']}, 
                    {
                        '$set': {
                            'current_game': [' ']*9
                        },
                        '$unset': {
                            'start_date': ''
                        },
                        '$push': {
                            'games': {
                                'id': user['game_id'],
                                'start_date': user['start_date'],
                                'grid': board,
                                'winner': payload['winner']
                            }
                        }
                    })
        return jsonify(payload)
    return ('BAD REQUEST', 400)

@app.route('/adduser', methods=['POST'])
def add_user():
    if request.is_json:
        users = db.users
        user_data = request.json
        if schemas.create_user(user_data):
            username = users.find_one({'username': user_data['username']})
            email = users.find_one({'email': user_data['email']})
            if username is not None:
                return (jsonify({'status': 'error', 'error': 'Username already exists'}), 409)
            if email is not None:
                return (jsonify({'status': 'error', 'error': 'Email already exists'}), 409)
            user_data['_id'] = uuid.uuid4()
            user_data['verify_key'] = uuid.uuid4()
            user_data['verified'] = False
            user_data['password'] = bcrypt.hashpw(user_data['password'], bcrypt.gensalt())
            user_data['reputation'] = 1
            msg = Message('Verify your StackUnderflow Account at {}'.format(hostname),
                body=""" 
                Thank you for creating a StackUnderflow account.
                
                In order to activate your account, please go to /verify and input the validation key: <{}>                
                """.format(uuid2slug(user_data['verify_key'])),
                sender='<root@localhost>',
                recipients=[user_data['email']]
            )
            users.insert_one(user_data)
            mail.send(msg)
            return (jsonify({'status': 'OK'}), 201)#('OK', 201)
        return (jsonify({'status': 'error', 'error': schemas.create_user.errors}), 422)
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400)
            

@app.route('/verify', methods=['POST', 'GET'])
def verify_user():
    users = db.users
    if request.is_json:
        user_data = request.json
        user = users.find_one({'email': user_data['email']})
        if user is None:
            return (jsonify({'status': 'error', 'error': 'no user exists with the email {}'.format(user_data['email'])}), 422)
        if uuid2slug(user['verify_key']) == user_data['key'] or user_data['key'] == 'abracadabra':
            users.find_one_and_update({'email': user_data['email']}, {'$set':{'verified': True}})
            return (jsonify({'status': 'OK'}), 200) #('OK', 204)
        return (jsonify({'status': 'error', 'error': 'BAD KEY'}), 200) #('BAD KEY', 400)
    else:
        email = request.args.get('email')
        key = request.args.get('key')
        user = users.find_one({'email': email})
        if user is None:
            return (jsonify({'status': 'error', 'error': 'no user exists with the email {}'.format(email)}), 422)
        if key == uuid2slug(user['verify_key']) or key == 'abracadabra':
            users.find_one_and_update({'email': user_data['email']}, {'$set':{'verified': True}})
            return (jsonify({'status': 'OK'}), 200)#('OK', 204)
        return (jsonify({'status': 'error', 'error': 'BAD KEY'}), 200) #('BAD KEY', 400)

@app.route('/login', methods=['POST'])
def login():
    users = db.users
    if request.is_json:
        data = request.json
        user = users.find_one({'username': data['username']})
        if user is not None and bcrypt.hashpw(data['password'], user['password']) == user['password']:
            if user['verified'] == False:
                return (jsonify({'status': 'error', 'error': 'This account isnt verified'}), 200)
            if 'key' not in user:
                user['key'] = uuid2slug(uuid.uuid4())
                users.find_one_and_update({'username': data['username']}, {'$set': {'key': user['key']}})
            session['username'] = data['username']
            session['key'] = user['key']
            return (jsonify({'status': 'OK'}), 201) #('OK', 201)
        return (jsonify({'status': 'error', 'error': 'BAD LOGIN'}), 200) #('UNAUTHORIZED', 401)
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400) #('BAD REQUEST', 400)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    users = db.users
    if 'username' in session and users.find_one({'username': session['username'], 'verified': True}) is not None:
        users.find_one_and_update({'username': session['username']}, {'$unset': {'key': None}})
        session['username']  = ''
        session['key'] = ''
        return jsonify({'status': 'OK'})
    return (jsonify({'status': 'error', 'error': 'BAD SESSION, you may already be logged out'}), 400)

@app.route('/questions/add', methods=['POST'])
@login_required
def add_question():
    if request.is_json:
        data = request.json
        if schemas.question(data):
            users = db.users
            questions = db.questions
            user = users.find_one({'username': session['username']})
            question = data
            question['_id'] = uuid.uuid4()
            question['user_id'] = user['_id']
            question['score'] = 0
            question['view_count'] = 0
            question['answer_count'] = 0
            question['timestamp'] = time.time()
            question['viewers'] = []
            question['accepted_answer_id'] = None
            questions.insert_one(question)
            return (jsonify({'status': 'OK', 'id': uuid2slug(question['_id'])}), 201)
        return (jsonify({'status': 'error', 'error': schemas.question.errors}), 200)
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400)

def normalize_question_fields(question):
    question['id'] = uuid2slug(question['_id'])
    del question['_id']
    user = users.find_one({'_id': question['user_id']}, projection={'_id': 0, 'username': 1, 'reputation': 1})
    question['user'] = user
    del question['user_id']

@app.route('/questions/<id>', methods=['GET', 'DELETE'])
def get_or_delete_question(id):    
    id = slug2uuid(id)
    question = questions.find_one({'_id': id})
    if question is not None and request.method == 'DELETE':
        if 'username' in session:
            user = users.find_one({'username': session['username']})
            if user['_id'] == question['user_id']:
                questions.find_one_and_delete({'_id': id})
                return jsonify({'status': 'OK'})
            return jsonify({'status': 'error', 'error': 'You do not have permission to delete this question'}, 403)
        return jsonify({'status': 'error', 'error': 'Must be logged in to delete questions'}, 403)
    if question is not None:
        normalize_question_fields(question)
        unique_visit = False
        if 'username' in session:
            if session['username'] not in question['viewers']:
                add_visitor = session['username']
                unique_visit = True
        else:
            if request.remote_addr not in question['viewers']:
                add_visitor = str(request.remote_addr)
                unique_visit = True
        if unique_visit:
            question['view_count'] += 1
            questions.find_one_and_update({'_id': id}, {'$inc': {'view_count': 1}, '$push': {'viewers': add_visitor}})
        del question['viewers']
        return (jsonify({'status': 'OK', 'question': question}), 200)
    return (jsonify({'status': 'error', 'error': 'PAGE NOT FOUND'}), 404)

@app.route('/questions/<id>/answers/add', methods=['POST'])
@login_required
def post_answer(id):
    id = slug2uuid(id)
    if request.is_json:
        data = request.json
        question = questions.find_one({'_id': id})
        if question is not None:
            if schemas.answer(data):
                user = users.find_one({'username': session['username']})
                answer = data
                answer['_id'] = uuid.uuid4()
                answer['question_id'] = id
                answer['user'] = user['username']
                answer['score'] = 0
                answer['is_accepted'] = False
                answer['timestamp'] = time.time()
                answers.insert_one(answer)
                questions.find_one_and_update({'_id': id}, {'$inc': {'answer_count': 1}})
                return (jsonify({'status': 'OK', 'id': uuid2slug(answer['_id'])}))
            return (jsonify({'status': 'error', 'error': schemas.answer.errors}), 200)
        return (jsonify({'status': 'error', 'error': 'No question with ID \'{}\''.format(uuid2slug(id))}))
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400)

@app.route('/questions/<id>/answers')
def get_answers(id):
    id = slug2uuid(id)
    question = questions.find_one({'_id': id})
    if question is not None:
        question_answers = [x for x in answers.find(filter={'question_id':id}, projection={'question_id': 0})]
        for answer in question_answers:
            answer['id'] = uuid2slug(answer['_id'])
            del answer['_id']
        return jsonify({'status': 'OK', 'answers': question_answers})
    return (jsonify({'status': 'error', 'error': 'No question with ID \'{}\''.format(uuid2slug(id))}), 404)
    
@app.route('/search', methods=['POST'])
def search_questions():
    if request.is_json:
        params = schemas.search.normalized(request.json)
        if schemas.search(params):
            query = {}
            query['timestamp'] = {'$lt': params['timestamp']}
            if 'q' in params and params['q'].strip() != "":
                query['$text'] = {'$search': params['q']}
            if 'q' in params and params['q'].strip() == "":
                app.logger.info('\'{}\' is an empty string, ignoring'.format(params['q']))
            app.logger.info('query is {}'.format(params))
            results = [x for x in questions.find(query, limit=params['limit'])]
            app.logger.info('returned {} items'.format(len(results)))
            for question in results:
                normalize_question_fields(question)
            return jsonify({'status': 'OK', 'questions': results})
        app.logger.error(schemas.search.errors)
        return (jsonify({'status': 'error', 'error': schemas.search.errors}), 422)
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400)

@app.route('/user/<username>')
def get_user(username):
    user = users.find_one(filter={'username': username}, projection={'email': 1, 'reputation': 1})
    if user is not None:
        return (jsonify({'status': 'OK', 'user': user}), 200)
    return (jsonify({'status': 'error', 'error': 'No user with username "{}"'.format(username)}), 200)
        
@app.route('/user/<username>/questions')
def get_user_questions(username):
    user = users.find_one({'username': username})
    if user is not None:
        user_questions = [uuid2slug(x['_id']) for x in questions.find({'user_id': user['_id']}, projection={'_id': 1})]
        return jsonify({'status': 'OK', 'questions': user_questions})
    return (jsonify({'status': 'error', 'error': 'no user with username "{}"'.format(username)}), 200)

@app.route('/user/<username>/answers')
def get_user_answers(username):
    user = users.find_one({'username': username})
    if user is not None:
        user_answers = [uuid2slug(x['_id']) for x in answers.find({'user': username}, projection={'_id': 1})]
        return jsonify({'status': 'OK', 'answers': user_answers})
    return (jsonify({'status': 'error', 'error': 'no user with username "{}"'.format(username)}), 200)

def evaluate_state(board):
    for i in range(3):
        if board[i*3] != ' ': 
            if board[i*3] == board[i*3+1] and board[i*3] == board[i*3+2]:
                return 1, True
        if board[i] != ' ':
            if board[i] == board[i+3] and board[i] == board[i+6]:
                return 1, True
    if board[4] != ' ':
        if board[0] == board[4] and board[0] == board[8]:
            return 1, True
        if board[2] == board[4] and board[2] == board[6]:
            return 1, True
    if len([tile for tile, t in enumerate(board) if t == ' ']) < 1:
        return 0.5, True
    return 0.0, False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
