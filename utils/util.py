from datetime import datetime, timedelta
import os
import jwt
from dotenv import load_dotenv
from functools import wraps
from flask import request, jsonify
from database import db
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
from models.role import Role

def encode_token(user_id):
    payload={
        'exp' : datetime.now()+timedelta(days=0, hours=1),
        'iat' : datetime.now(),
        'sub' : user_id
    }
    token = jwt.encode(payload,SECRET_KEY,algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
                print("Token:", token)
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'token has expired', 'error': 'Unauthorized'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token', 'error': 'Unauthorized'}), 401
        else:
            return jsonify({'message': 'Authentication Token is missing', 'error': 'Unauthorized'}), 401
        
        return f(*args, **kwargs)
    return decorated


def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id = getattr(request, 'user_id', None)
            if not user_id:
                return jsonify({'message': 'Unauthorized access', 'error': 'Unauthorized'}), 401
            user = db.session.query(Role).filter_by(id=user_id).first()
            if not user or user.role not in roles:
                return jsonify({'message': 'Access denied', 'error': 'Forbidden'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
