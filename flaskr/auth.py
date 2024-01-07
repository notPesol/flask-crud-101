import datetime

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
from .common.dto import ResponseDTO
from .common.enum import Message

from .new_db import new_db, User

from sqlalchemy import select, update

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.get('/me')
@jwt_required()
def get_profile():
    # Access the identity of the current user with get_jwt_identity
    dict_user = get_jwt_identity()

    responseDTO = ResponseDTO(data=dict_user)
    
    return jsonify(responseDTO.to_dict()), responseDTO.status

@bp.post('/')
def register():
    body: dict = request.json
    
    username = body.get('username')
    password = body.get('password')
    error = None
    
    if not username:
        error = 'Username is required'
    elif not password:
        error = 'Password is required'
        
    responseDTO = ResponseDTO()
    
    if error:
        responseDTO.data = error
        responseDTO.message = Message.ERROR.value
        responseDTO.status = 400
    else:
        try:
            new_user = User()
            new_user.username = username
            new_user.password = generate_password_hash(password, method='pbkdf2')
    
            new_db.session.add(new_user)
            new_db.session.commit()
        
            new_user = get_user_by_id(new_user.id)
                        
            responseDTO.data = new_user._asdict()

        except Exception:
            responseDTO.data = f"User {username} is already registered"
            responseDTO.message = Message.ERROR.value
            responseDTO.status = 409
        
    return jsonify(responseDTO.to_dict()), responseDTO.status

@bp.put('/')
def change_password():
    body: dict = request.json
    
    username = body.get('username')
    old_password = body.get('old_password')
    new_password = body.get('new_password')
    error = None
    
    if not username:
        error = 'Username is required'
    elif not old_password:
        error = 'Old password is required'
    elif not new_password:
        error = 'New password is required'
        
    responseDTO = ResponseDTO()
    
    if error:
        responseDTO.data = error
        responseDTO.message = Message.ERROR.value
        responseDTO.status = 400
    else:
        try:
            user = get_by_username(username)
            
            if user is None:
                responseDTO.status = 404
                raise Exception('Incorrect username')
            elif not check_password_hash(user._asdict()['password'], old_password):
                responseDTO.status = 401
                raise Exception('Incorrect old password')
            
            stmt = update(User).where(User.username == username).values(
                password=generate_password_hash(new_password, method='pbkdf2')).returning(User.id, User.username)

            user = new_db.session.execute(stmt).first()
            responseDTO.data = user._asdict()
        except Exception as e:
            responseDTO.data = str(e)
            responseDTO.message = Message.ERROR.value
        
    return jsonify(responseDTO.to_dict()), responseDTO.status

@bp.get('/<int:id>')
def get_by_id(id: int):
    responseDTO = ResponseDTO()
    
    try:
        user = get_user_by_id(id=id)
        
        if user is None:
            raise Exception(f"User #{id} not found")
        
        responseDTO.data = user._asdict()
    except Exception as e:
        responseDTO.data = str(e)
        responseDTO.message = Message.ERROR.value
        responseDTO.status = 404
        
    return jsonify(responseDTO.to_dict()), responseDTO.status

@bp.delete('/<int:id>')
def delete_by_id(id: int):
    responseDTO = ResponseDTO()
    
    db = get_db()
    db.execute("DELETE FROM user WHERE id = ?", (id,))
    db.commit()
    
    return jsonify(responseDTO.to_dict()), responseDTO.status

    
@bp.get('/')
def get():
    
    page = max(1, int(request.args.get('page', 1)))
    limit = max(1, int(request.args.get('limit', 20)))
    offset = (page - 1) * limit
    
    responseDTO = ResponseDTO()
    
    try:
        responseDTO.count = new_db.session.query(User).count()
        
        users = new_db.session.query(User.id, User.username).limit(limit).offset(offset)
        user_list = [{'id': user.id, 'username': user.username} for user in users]
        responseDTO.data = user_list
    except Exception as e:
        responseDTO.data = str(e)
        responseDTO.message = Message.ERROR.value
        
    return jsonify(responseDTO.to_dict())

@bp.post('/login')
def login():
    body: dict = request.json
    
    username = body.get('username')
    password = body.get('password')
    error = None
    
    if not username:
        error = 'Username is required'
    elif not password:
        error = 'Password is required'
        
    responseDTO = ResponseDTO()
    
    if error:
        responseDTO.data = error
        responseDTO.message = Message.ERROR.value
        responseDTO.status = 400
    else:        
        user = new_db.session.execute(select(User.id, User.username, User.password).where(User.username==username)).first()
        
        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user._asdict()['password'], password):
            error = 'Incorrect password.'          
        
        if error:
            responseDTO.data = error
            responseDTO.message = Message.ERROR.value  
            responseDTO.status = 401
        else:
            dict_user = user._asdict()
            dict_user.pop('password')
            
            access_token = create_access_token(identity=dict_user, expires_delta=datetime.timedelta(days=1))
            responseDTO.data = { 'user': dict_user ,'access_token': access_token }
    
    return jsonify(responseDTO.to_dict()), responseDTO.status
    
    
def get_by_username(username: str):
    return new_db.session.execute(select(User.id, User.username, User.password).where(User.username==username)).first()

def get_user_by_id(id: int):
    return new_db.session.execute(select(User.id, User.username).where(User.id==id)).first()