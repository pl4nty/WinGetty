import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_htmx import HTMX
from datetime import datetime
from distutils.version import LooseVersion
from config import settings
from dynaconf import FlaskDynaconf
from .utils import basedir
from flask_login import LoginManager

db = SQLAlchemy()
htmx = HTMX()
dynaconf = FlaskDynaconf()

def sort_versions(versions):
    return sorted(versions, key=lambda x: LooseVersion(x.version_code), reverse=True)


def create_app():
    app = Flask(__name__)
    app.config.from_object(settings)
    db.init_app(app)
    htmx.init_app(app)
    dynaconf.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = ''
    login_manager.init_app(app)

    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.ui_routes import ui
    from app.api_routes import api
    from app.auth_routes import auth
    app.register_blueprint(ui)
    app.register_blueprint(api)
    app.register_blueprint(auth)
    
    

    app.jinja_env.filters['sort_versions'] = sort_versions

    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    with app.app_context():
        db.create_all()
    return app