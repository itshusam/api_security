from sqlalchemy.orm import Session
from database import db
from models.product import Product
from circuitbreaker import circuit
from sqlalchemy import select
from flask_sqlalchemy import pagination
from utils.util import role_required
def fallback_function(product_data):
    return None

@circuit(failure_threshold=1, recovery_timeout=10, fallback_function=fallback_function)
@role_required(['admin'])
def save(product_data):
    try:
        with Session(db.engine) as session:
            with session.begin():
                new_product = Product(
                    name=product_data['name'], 
                    price=product_data['price']
                )
                session.add(new_product)
                session.commit()
                session.refresh(new_product)

            return new_product
    except Exception as e:
        raise e

def find_all(page=1, per_page=10):
    try:
        query = select(Product)
        paginated_products = db.session.execute(query).scalars().paginate(page=page, per_page=per_page)

        return paginated_products
    except Exception as e:
        raise e
