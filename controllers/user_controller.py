from flask import request, jsonify
from models.user import User
from services.userService import find_by_username 
from utils import encode_token

def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = find_by_username(username)
    
    if user and user.check_password(password):
        token = encode_token(user.id)
        return jsonify({'token': token, 'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401