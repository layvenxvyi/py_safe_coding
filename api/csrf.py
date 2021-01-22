#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2021-01-20 18:44
# @Author   :   layven
'''
-CSRF跨域请求伪造，指攻击者盗用了你的身份，以你的名义发送恶意请求。包括：以你名义发送邮件，发消息，盗取你的账号，甚至于购买商品，虚拟货币转账......造成个人隐私泄露以及财产安全。
-防御：在关键请求接口使用token机制/验证码/支付时重新验证otp等
-token机制：
1. 后端首先需要开启第三方框架的CSRF保护，
    (1) 前后端不分离：falsk_wtf.csrf实现，django.views.decorators.csrf，在不需要保护的路由上当加上:@csrf.exempt
    (2) 前后端分离：jwt，登陆态取token值，之后每次请求校验token值再返回数据
   参考：https://cloud.tencent.com/developer/article/1546214
2. 前端取后台返回的csrf_token：
如jinja2的<input type="hidden" name="csrf_token" value="{{csrf_token()}}">
'''
from flask_wtf.csrf import CSRFProtect
from flask_restful import Resource,reqparse
csrfparm=reqparse.RequestParser()
csrfparm.add_argument('name',type=str,required=False,help='姓名')
csrfparm.add_argument('type',type=str,required=False,help='注入类型')

def init_csrf(app):
    #前后端不分离可用此方法
    app.config['SECRET_KEY'] = 'you never guess'
    csrf = CSRFProtect(app)
    csrf.init_app(app)

class csrf(Resource):
    def get(self):
        par=csrfparm.parse_args()
        name=par.get('name','')
        type=par.get('type','')
        return