from flask import Flask
from database import db
from schema import ma
from limiter import limiter
from models.customer import Customer
from models.employee import Employee
from models.order import Order
from models.product import Product
from models.production import Production
from routes.employeeBP import employee_blueprint
from routes.customerBP import customer_blueprint
from routes.orderBP import order_blueprint
from routes.productBP import product_blueprint
from routes.productionBP import production_blueprint
from routes.customerBP import customer_blueprint
from routes.taskTwoBP import analytics_blueprint
from caching import cache
from flask_cors import CORS
from routes.userBP import auth_blueprint
def create_app(config_name):
    app = Flask(__name__)

    app.config.from_object(f'config.{config_name}')
    db.init_app(app)
    ma.init_app(app)
    cache.init_app(app)
    limiter.unit_app(app)
    CORS(app)
    return app

def blue_print_config(app):
    app.register_blueprint(customer_blueprint, url_prefix='/customers')
    app.register_blueprint(employee_blueprint, url_prefix='/employees')
    app.register_blueprint(product_blueprint, url_prefix='/products')
    app.register_blueprint(order_blueprint, url_prefix='/orders')
    app.register_blueprint(production_blueprint, url_prefix='/productions')
    app.register_blueprint(analytics_blueprint, url_prefix='/analytics')
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
def configure_rate_limit():
    limiter.limit("5 per day")(customer_blueprint)



if __name__ == '__main__':
    app = create_app('DevelopmentConfig')

    blue_print_config(app)
    configure_rate_limit()

    with app.app_context():
        db.drop_all()
        db.create_all()

    app.run(debug=True)