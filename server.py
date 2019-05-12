import base64
import csv
import datetime
import logging
import os
import random
import re
import smtplib
import sys
import time
import uuid
import threading
from email.message import EmailMessage
from email.policy import SMTP
from functools import wraps

import bcrypt
from cassandra.cluster import Cluster
from flask import (Flask, jsonify, make_response, render_template, request,
                   session)
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.utils import secure_filename

import schemas
from static.RL_learn.learner import Game, Learner

here = os.path.dirname(__file__)
sys.path.insert(0, here)

# section below for converting uuid to base64 (a.k.a. a slug) and visa versa
#--------------------------------------------
def uuid2slug(id):
    return base64.b64encode(id.bytes).decode('utf-8').rstrip('=\n').replace('/', '_').replace('+', '-')

def slug2uuid(slug):
    return uuid.UUID(bytes=(base64.b64decode(slug.replace('_', '/').replace('-', '+') + '==')))
#--------------------------------------------

image_types = ['jpeg', 'jpg', 'png', 'gif']
video_types = ['mp4']

app = Flask(__name__, static_url_path='')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
mail = Mail(app)
agent = Learner(epsilon=0)
agent.load_states(os.path.join(here, 'static/RL_learn/playero.pickle'))

with open(os.path.join(here, 'static/images.csv'), 'r') as f:
    images = f.readlines()

streamhndlr = logging.StreamHandler()
app.logger.setLevel(logging.INFO)

client = MongoClient('64.190.90.55', 27017)
db = client.stcku
users = db.users
questions = db.questions
answers = db.answers

cluster = Cluster(['64.190.90.55'])
sesh = cluster.connect()
sesh.execute("CREATE KEYSPACE IF NOT EXISTS stcku WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '2' }")
sesh.set_keyspace('stcku')
sesh.execute('CREATE TABLE IF NOT EXISTS media ( id uuid PRIMARY KEY, name text, user text, content blob )')

queued_media = set()

hostname='StackUnderflow'

def login_required(f):
    @wraps(f)
    def check_login(*args, **kwargs):
        if 'username' in session and 'key' in session and session['username'] != '' and session['key'] != '':
            users = db.users
            user = users.find_one({'username': session['username']})
            if user is None:
                return (jsonify({'status': 'error', 'error': 'Bad cookies, reference non-existent user'}), 400)
            if user['verified'] == False:
                return (jsonify({'status': 'error', 'error': 'Account requires verification'}), 403)
            if user is not None and session['key'] == user['key']:
                return f(*args, **kwargs)
        return (jsonify({'status': 'error', 'error': 'Must be logged in to access this resource'}), 403) #('UNAUTHORIZED', 401)
    return check_login

def validate_id(id):
    if re.match(r'^[0-9A-Za-z_-]{22}$', id) is None:
        return False
    slug = uuid2slug(slug2uuid(id))
    return id == slug
            

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

def send_mail(msg):
    mail.send(msg)

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
            t = threading.Thread(target=send_mail, args=(msg, ))
            t.start()
            t.run() # mail.send(msg)
            return (jsonify({'status': 'OK'}), 201)#('OK', 201)
        # app.logger.info(schemas.create_user.errors)
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
        return (jsonify({'status': 'error', 'error': 'BAD KEY'}), 400) #('BAD KEY', 400)
    else:
        email = request.args.get('email')
        key = request.args.get('key')
        user = users.find_one({'email': email})
        if user is None:
            return (jsonify({'status': 'error', 'error': 'no user exists with the email {}'.format(email)}), 422)
        if key == uuid2slug(user['verify_key']) or key == 'abracadabra':
            users.find_one_and_update({'email': user_data['email']}, {'$set':{'verified': True}})
            return (jsonify({'status': 'OK'}), 200)#('OK', 204)
        return (jsonify({'status': 'error', 'error': 'BAD KEY'}), 400) #('BAD KEY', 400)

@app.route('/login', methods=['POST'])
def login():
    users = db.users
    if request.is_json:
        data = request.json
        user = users.find_one({'username': data['username']})
        if user is not None and bcrypt.hashpw(data['password'], user['password']) == user['password']:
            if user['verified'] == False:
                return (jsonify({'status': 'error', 'error': 'This account isnt verified'}), 403)
            if 'key' not in user:
                user['key'] = uuid2slug(uuid.uuid4())
                users.find_one_and_update({'username': data['username']}, {'$set': {'key': user['key']}})
            session['username'] = data['username']
            session['key'] = user['key']
            return (jsonify({'status': 'OK'}), 200) #('OK', 201)
        return (jsonify({'status': 'error', 'error': 'BAD LOGIN'}), 403) #('UNAUTHORIZED', 401)
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
            if 'media' in data:
                if len(data['media']) < 1:
                    del data['media']
                else:
                    app.logger.info(data['media'])
                    for media in data['media']:
                        media_file = [x for x in sesh.execute('SELECT * FROM media WHERE id=%s', [slug2uuid(media)])]
                        if len(media_file) < 1:
                            return (jsonify({'status': 'error', 'error': 'No media found with id {}'.format(media)}), 404)
                        if media_file[0].user != session['username']:
                            return (jsonify({'status': 'error', 'error': 'You are not the original poster of the included media'}), 409)
                    media_ids = questions.find({}).distinct('media')
                    for media in data['media']:
                        if media in media_ids:
                            return (jsonify({'status': 'error', 'error': 'media {} is already used in another question'.format(media)}), 409)
                    media_ids = answers.find({}).distinct('media')
                    for media in data['media']:
                        if media in media_ids:
                            return (jsonify({'status': 'error', 'error': 'media {} is already used in another question'.format(media)}), 409)
            user = users.find_one({'username': session['username']})
            question = data
            question['_id'] = uuid.uuid4()
            question['user_id'] = user['_id']
            question['score'] = 0
            question['view_count'] = 0
            question['answer_count'] = 0
            question['timestamp'] = time.time()
            question['viewers'] = []
            question['voters'] = {}
            question['accepted_answer_id'] = None
            questions.insert_one(question)
            return (jsonify({'status': 'OK', 'id': uuid2slug(question['_id'])}), 201)
        # app.logger.info(schemas.question.errors)
        return (jsonify({'status': 'error', 'error': schemas.question.errors}), 422)
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400)

def normalize_question_fields(question):
    question['id'] = uuid2slug(question['_id'])
    del question['_id']
    user = users.find_one({'_id': question['user_id']}, projection={'_id': 0, 'username': 1, 'reputation': 1})
    question['user'] = user
    del question['user_id']
    if question['accepted_answer_id'] is not None:
        question['accepted_answer_id'] = uuid2slug(question['accepted_answer_id'])
    del question['viewers']
    del question['voters']
    if 'media' not in question:
        question['media'] = []

def undo_votes(item):

    amt = 0
    for user, votes in item['voters']:
        if 'waived' in votes and votes['waived'] and not votes['upvote']:
            pass
        else:
            if votes['upvote']:
                amt -= -1
            elif votes['upvote'] is not None:
                amt += 1
    if 'user_id' in item:
        while amt != 0:
            query = {'_id': item['user_id']}
            if amt < 0:
                query['reputation'] = {'$gt': 1}
            users.find_one_and_update(query, {'$inc': {'reputation': 1 if amt > 0 else -1}})
            amt += 1 if amt < 0 else -1
    elif 'user' in item:
        while amt != 0:
            query = {'username': item['user']}
            if amt < 0:
                query['reputation'] = {'$gt': 1}
            users.find_one_and_update(query, {'$inc': {'reputation': 1 if amt > 0 else -1}})
            amt += 1 if amt < 0 else -1

@app.route('/questions/<id>', methods=['GET', 'DELETE'])
def get_or_delete_question(id):  
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'PAGE NOT FOUND'}), 404)
    id = slug2uuid(id)
    question = questions.find_one({'_id': id})
    if question is not None and request.method == 'DELETE':
        if 'username' in session and 'key' in session and session['username'] != '' and session['key'] != '':
            user = users.find_one({'username': session['username']})
            if user['verified'] == False:
                return (jsonify({'status': 'error', 'error': 'Account requires verification'}), 403)
            if user is not None and session['key'] == user['key']:
                user = users.find_one({'username': session['username']})
                if user['_id'] == question['user_id']:
                    undo_votes(question)
                    questions.find_one_and_delete({'_id': id})
                    ans = answers.find({'question_id': id})
                    for answer in ans:
                        if 'media' in answer:
                            app.logger.info('deleting {}'.format(answer['media']))
                            for media_id in answer['media']:
                                sesh.execute('DELETE FROM media WHERE id=%s', [slug2uuid(media_id)])
                        undo_votes(answer)
                        answers.find_one_and_delete({'_id': answer['_id']})
                    if 'media' in question:
                        app.logger.info('deleting {}'.format(question['media']))
                        for media_id in question['media']:
                            sesh.execute('DELETE FROM media WHERE id=%s', [slug2uuid(media_id)])
                    return (jsonify({'status': 'OK'}))
                return (jsonify({'status': 'error', 'error': 'You do not have permission to delete this question'}), 403)
        return (jsonify({'status': 'error', 'error': 'Must be logged in to delete questions'}), 403)
    if question is not None:
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
        normalize_question_fields(question)
        return (jsonify({'status': 'OK', 'question': question}), 200)
    return (jsonify({'status': 'error', 'error': 'PAGE NOT FOUND'}), 404)

@app.route('/questions/<id>/answers/add', methods=['POST'])
@login_required
def post_answer(id):
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'Question not found'}), 404)
    id = slug2uuid(id)
    if request.is_json:
        data = request.json
        question = questions.find_one({'_id': id})
        if question is not None:
            if schemas.answer(data):
                if 'media' in data:
                    if len(data['media']) < 1:
                        del data['media']
                    else:
                        for media in data['media']:
                            media_file = [x for x in sesh.execute('SELECT * FROM media WHERE id=%s', [slug2uuid(media)])]
                            if len(media_file) < 1:
                                return (jsonify({'status': 'error', 'error': 'No media found with id {}'.format(media)}), 404)
                            if media_file[0].user != session['username']:
                                return (jsonify({'status': 'error', 'error': 'You are not the original poster of the included media'}), 409)
                        media_ids = questions.find({}).distinct('media')
                        for media in data['media']:
                            if media in media_ids:
                                return (jsonify({'status': 'error', 'error': 'media {} is already used in another question'.format(media)}), 409)
                        media_ids = answers.find({}).distinct('media')
                        for media in data['media']:
                            if media in media_ids:
                                return (jsonify({'status': 'error', 'error': 'media {} is already used in another question'.format(media)}), 409)
                user = users.find_one({'username': session['username']})
                answer = data
                answer['_id'] = uuid.uuid4()
                answer['question_id'] = id
                answer['user'] = user['username']
                answer['score'] = 0
                answer['voters'] = {}
                answer['is_accepted'] = False
                answer['timestamp'] = time.time()
                answers.insert_one(answer)
                questions.find_one_and_update({'_id': id}, {'$inc': {'answer_count': 1}})
                return (jsonify({'status': 'OK', 'id': uuid2slug(answer['_id'])}))
            # app.logger.info(schemas.answer.errors)
            return (jsonify({'status': 'error', 'error': schemas.answer.errors}), 422)
        return (jsonify({'status': 'error', 'error': 'No question with ID \'{}\''.format(uuid2slug(id))}), 404)
    return (jsonify({'status': 'error', 'error': 'Request type must be JSON'}), 400)

@app.route('/questions/<id>/answers')
def get_answers(id):
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'Question not found'}), 404)
    id = slug2uuid(id)
    question = questions.find_one({'_id': id})
    if question is not None:
        question_answers = [x for x in answers.find(filter={'question_id':id}, projection={'question_id': 0})]
        for answer in question_answers:
            answer['id'] = uuid2slug(answer['_id'])
            del answer['_id']
            del answer['voters']
            if 'media' not in answer:
                question['media'] = []
        return jsonify({'status': 'OK', 'answers': question_answers})
    return (jsonify({'status': 'error', 'error': 'No question with ID \'{}\''.format(uuid2slug(id))}), 404)
    
@app.route('/search', methods=['POST'])
def search_questions():
    if request.is_json:
        params = schemas.search.normalized(request.json)
        if schemas.search(params):
            query = {}
            query['timestamp'] = {'$lt': params['timestamp']}
            if 'tags' in params:
                query['tags'] = {'$all': params['tags']}
            if params['accepted']:
                query['accepted_answer_id'] = {'$ne': None}
            if params['has_media']:
                query['media'] = {'$ne': None}
            if 'q' in params and params['q'].strip() != "":
                query['$text'] = {'$search': params['q']}
            if 'q' in params and params['q'].strip() == "":
                app.logger.info('\'{}\' is an empty string, ignoring'.format(params['q']))
            app.logger.info('query is {}'.format(params))
            results = [x for x in questions.find(query, limit=params['limit']).sort(params['sort_by'], -1)]
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
    return (jsonify({'status': 'error', 'error': 'No user with username "{}"'.format(username)}), 404)
        
@app.route('/user/<username>/questions')
def get_user_questions(username):
    user = users.find_one({'username': username})
    if user is not None:
        user_questions = [uuid2slug(x['_id']) for x in questions.find({'user_id': user['_id']}, projection={'_id': 1})]
        return jsonify({'status': 'OK', 'questions': user_questions})
    return (jsonify({'status': 'error', 'error': 'no user with username "{}"'.format(username)}), 404)

@app.route('/user/<username>/answers')
def get_user_answers(username):
    user = users.find_one({'username': username})
    if user is not None:
        user_answers = [uuid2slug(x['_id']) for x in answers.find({'user': username}, projection={'_id': 1})]
        return jsonify({'status': 'OK', 'answers': user_answers})
    return (jsonify({'status': 'error', 'error': 'no user with username "{}"'.format(username)}), 404)

@app.route('/questions/<id>/upvote', methods=['POST'])
@login_required
def upvote_question(id):
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'Question not found'}), 404)
    id = slug2uuid(id)
    if request.is_json:
        params = schemas.upvote.normalized(request.json)
        if schemas.upvote(params):
            upvote = params['upvote']
            question = questions.find_one({'_id': id})
            if question is not None:
                amt = 1 if upvote else -1
                waived = False
                if session['username'] in question['voters']:
                    prev_upvote = question['voters'][session['username']]['upvote']
                    if 'waived' in question['voters'][session['username']]:
                        waived = question['voters'][session['username']]['waived']
                    if upvote == prev_upvote:
                        amt = -amt
                        upvote = None
                    elif prev_upvote is not None:
                        amt += amt
                questions.find_one_and_update({'_id': id}, {'$inc': {'score': amt}, '$set': {'voters.{}.upvote'.format(session['username']): upvote}})
                query = {'_id': question['user_id']}
                if amt > 1 and waived:
                    amt = 1
                    questions.find_one_and_update({'_id': id}, {'$set': {'voters.{}.waived'.format(session['username']): False}})
                while amt != 0:
                    if amt < 0:
                        query['reputation'] = {'$gt': 1}
                    result = users.find_one_and_update(query, {'$inc': {'reputation': 1 if amt > 0 else -1}})
                    if result is None:
                        questions.find_one_and_update({'_id': id}, {'$set': {'voters.{}.waived'.format(session['username']): True}})
                    amt += 1 if amt < 0 else -1
                return (jsonify({'status': 'OK'}), 200)
            return (jsonify({'status': 'error', 'error': 'No question found with given id'}), 404)
        return (jsonify({'status': 'error', 'error': schemas.upvote.errors}), 422)
    return (jsonify({'status': 'error', 'error': 'Bad request, must send JSON'}), 400)
        
@app.route('/answers/<id>/upvote', methods=['POST'])
@login_required
def upvote_answer(id):
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'Answer not found'}), 404)
    id = slug2uuid(id)
    if request.is_json:
        params = schemas.upvote.normalized(request.json)
        if schemas.upvote(params):
            upvote = params['upvote']
            answer = answers.find_one({'_id': id})
            if answer is not None:
                amt = 1 if upvote else -1
                waived = False
                if session['username'] in answer['voters']:
                    prev_upvote = answer['voters'][session['username']]['upvote']
                    if 'waived' in answer['voters'][session['username']]:
                        waived = answer['voters'][session['username']]['waived']
                    if upvote == prev_upvote:
                        amt = -amt
                        upvote = None
                    elif prev_upvote is not None:
                        amt += amt
                answers.find_one_and_update({'_id': id}, {'$inc': {'score': amt}, '$set': {'voters.{}.upvote'.format(session['username']): upvote}})
                query = {'username': answer['user']}
                if amt > 1 and waived:
                    amt = 1
                    answers.find_one_and_update({'_id': id}, {'$set': {'voters.{}.waived'.format(session['username']): False}})
                while amt != 0:
                    if amt < 0:
                        query['reputation'] = {'$gt': 1}
                    result = users.find_one_and_update(query, {'$inc': {'reputation': 1 if amt > 0 else -1}})
                    if result is None:
                        answers.find_one_and_update({'_id': id}, {'$set': {'voters.{}.waived'.format(session['username']): True}})
                    amt += 1 if amt < 0 else -1
                return (jsonify({'status': 'OK'}), 200)
            return (jsonify({'status': 'error', 'error': 'No answer found with given id'}), 404)
        return (jsonify({'status': 'error', 'error': schemas.upvote.errors}), 422)
    return (jsonify({'status': 'error', 'error': 'Bad request, must send JSON'}), 400)

@app.route('/answers/<id>/accept', methods=['POST'])
@login_required
def accept_answer(id):
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'Answer not found'}), 404)
    id = slug2uuid(id)
    answer = answers.find_one({'_id': id})
    if answer is not None:
        question = questions.find_one({'_id': answer['question_id']})
        if question['accepted_answer_id'] is None:
            user = users.find_one({'_id': question['user_id']})
            if user['username'] == session['username']:
                questions.find_one_and_update({'_id': answer['question_id']}, {'$set': {'accepted_answer_id': answer['_id']}})
                answers.find_one_and_update({'_id': id}, {'$set': {'is_accepted': True}})
                return (jsonify({'status': 'OK'}), 200)
            return (jsonify({'status': 'error', 'error': 'You are not the original asker of this question'}), 403)
        return (jsonify({'status': 'error', 'error': 'There is already an accepted answer'}), 400)
    return (jsonify({'status': 'error', 'error': 'There is no answer with the given id'}), 404)

def insert_success(rows):
    for row in rows:
        if row.id in queued_media:
            queued_media.remove(row.id)


@app.route('/addmedia', methods=['POST'])
@login_required
def add_media():
    if 'content' in request.files:
        json = {
            'id': uuid.uuid4(),
            'name': secure_filename(request.files['content'].filename),
            'user': session['username'],
            'content': request.files['content'].stream.read()
        }
        insert = sesh.execute_async('INSERT INTO media (id, name, user, content) VALUES (%(id)s, %(name)s, %(user)s, %(content)s)', json)
        insert.add_callback(insert_success)
        queued_media.add(json['id'])
        return (jsonify({'status': 'OK', 'id': uuid2slug(json['id'])}))
    return (jsonify({'status': 'error', 'error': 'no content sent'}), 400)

@app.route('/media/<id>')
def get_media(id):
    if not validate_id(id):
        return (jsonify({'status': 'error', 'error': 'Media not found'}), 404)
    id = slug2uuid(id)
    media = [x for x in sesh.execute('SELECT * FROM media WHERE id=%s', [id])]
    if len(media) > 0:
        media = media[0]
        resp = make_response(media.content)
        m = re.search(r'^.*\.(.*)$', media.name)
        if m.group(1) in image_types:
            resp.headers['Content-Type'] = 'image/{}'.format('jpeg' if m.group(1) == 'jpg' else m.group(1))
        else:
            resp.headers['Content-Type'] = 'video/{}'.format(m.group(1))
        return resp
    return ('media not found', 404)
    
@app.route('/reset')
def reset_databases():
    questions.drop()
    answers.drop()
    users.drop()
    sesh.execute("DROP TABLE IF EXISTS media")
    sesh.execute('CREATE TABLE IF NOT EXISTS media ( id uuid PRIMARY KEY, name text, user text, content blob )')
    return ('reset successful', 200)

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
