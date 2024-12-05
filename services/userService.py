from sqlalchemy.orm import Session
from database import db
from models.user import User

def find_by_username(username: str):
    with Session(db.engine) as session:
        user = session.query(User).filter(User.username == username).first()
        return user