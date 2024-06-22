import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')

    MAIL_SERVER = os.environ.get('MAIL_SERVER') ## sınavda çıkar mail serverı arıyor
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25) ## yoksa 25 alıyor
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None ## mail use tls varsa al yoksa boş bırak true false gibi
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['your-email@example.com'] ## hata olunca kime mail gidecek
    POSTS_PER_PAGE = 3