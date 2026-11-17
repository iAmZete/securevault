"""Flask extension instances (initialised in the application factory)."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(get_remote_address)
talisman = Talisman()
