from sqlalchemy import inspect
from app import app, db

with app.app_context():
    inspector = inspect(db.engine)
    constraints = inspector.get_foreign_keys('message')
    for constraint in constraints:
        print(constraint['name'])
