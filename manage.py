# -*-coding:utf-8 -*-
# @Time     :   2020/4/24 23:19
# @Author   :   layven
from flask import Flask, render_template
from flask_script import Manager
from api import init_api
from models import init_ext
# from api.csrf import init_csrf
# import pymysql
# pymysql.install_as_MySQLdb()
from flask_cors import CORS

app=Flask(__name__)
init_ext(app)
init_api(app)
# init_csrf(app)
cors = CORS(app, resources={r"/.*": {"origins": ["http://127.0.0.1:8080"]}})   # 只允许特定几个域名跨域

class Config(object):
    #sqlalchemy的配置参数
    SQLALCHEMY_DATABASE_URI="mysql://threaten:threaten@127.0.0.1:3306/threaten"
    #设置sqlalchemy自动跟踪数据库
    SQLALCHEMY_TRACK_MODIFICATIONS=True
app.config.from_object(Config)# 加载配置


@app.route('/')
def index():
    return render_template('helloworld.html')

def runserver():
    app.run(host='0.0.0.0',port=8888,debug=True,threaded=True)

manager=Manager(app)
manager.add_command('threaed',runserver())

if __name__=='__main__':
    manager.run()
#     app.run(host='0.0.0.0',port=8888,debug=True,use_reloader=False)#debug模式默认会对程序再执行一次，所以后面要加use_reloader=Flase，不写端口则默认5000


