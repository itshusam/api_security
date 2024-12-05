class DevelopmentConfig:
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:password@localhost/advanced_ecommerce_db'
    CACHE_TYPE = 'SimpleCache'
    DEBUG = True