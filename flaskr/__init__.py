import os

from flask import Flask
from flask_jwt_extended import JWTManager
from . import db
from . import auth
from .new_db import new_db

from dotenv import load_dotenv

load_dotenv()

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    
    # Setup the Flask-JWT-Extended extension
    app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
    jwt = JWTManager(app)
        
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
        
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(app.instance_path, 'flaskr.sqlite')),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    new_db.init_app(app)
    
    app.register_blueprint(auth.bp)
    
    with app.app_context():
        new_db.create_all()


    return app