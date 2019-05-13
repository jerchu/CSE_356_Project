from cerberus import Validator, TypeDefinition
from uuid import UUID
import time

uuid_type = TypeDefinition('uuid', (UUID), ())

Validator.types_mapping['uuid'] = uuid_type

create_user = Validator({
    'username': {
        'type': 'string',
        'regex': '[\w0-9_.-]+', #pylint: disable=W1401
        'required': True,
    },
    'password': {
        'type': 'string',
        'required': True,
    },
    'email': {
        'type': 'string',
        'regex': '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', # ensures emails are in email format #pylint: disable=W1401
        'required': True,
    },
})

question = Validator({
    'title': {
        'type': 'string',
        'required': True,
    },
    'body': {
        'type': 'string',
        'required': True,
    },
    'tags': {
        'type': 'list',
        'required': True,
        'schema': {
            'type': 'string',
        },
    },
    'media':{
        'type': 'list',
        'schema': {
            'type': 'string',
            'regex': '^[0-9A-Za-z_-]{22}$',
        },
    },
})

answer = Validator({
    'body': {
        'type': 'string',
        'required': True,
    },
    'media':{
        'type': 'list',
        'schema': {
            'type': 'string',
            'regex': '^[0-9A-Za-z_-]{22}$',
        },
    },
})

search = Validator({
    'timestamp': {
        'type': 'float',
        'default_setter': lambda doc: time.time(),
    },
    'limit':{
        'type': 'integer',
        'default': 25,
        'max': 100,
        'min': 0,
    },
    'q':{
        'type': 'string',
    },
    'sort':{
        'type': 'string',
        'allowed': ['timestamp', 'score'],
        'default': 'score',
    },
    'tags':{
        'type': 'list',
        'schema':{
            'type': 'string',
        }
    },
    'has_media':{
        'type': 'boolean',
        'default': False,
    },
    'accepted':{
        'type': 'boolean',
        'default': False,
    },
})

upvote = Validator({
    'upvote': {
        'type': 'boolean',
        'default': True,
    },
})