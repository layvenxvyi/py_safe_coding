'''
-XSS俗称跨站脚本攻击，是指攻击者通过”HTML注入”篡改网页，插入恶意脚本，从而在用户浏览网页时控制用户浏览器，危害：窃取cookie、放蠕虫、网站钓鱼等
-防护：宁死也不让数据变成可执行的代码，不信任任何用户的数据，严格区分数据和代码。
    1.输入校验：根据业务规则严格校验输入格式，如数据类型为纯数字，限制长度等，若由于业务需要无法限制则使用输出编码
    2.输出编码：哪里有漏洞则在哪里对返回进行html实体编码
    注意：应用程序对同一输入不做两次解码，否则容易使用多次编码进行绕过；过滤器应防护多种请求格式，get/post/multipart
-html富文本过滤器思路：暂未提供该过滤器修复代码
              |-不在白名单内-X【干掉】
        |--[取标签]       |-剩下的-escape-------------------------|
        |     |------[在白名单]         |-不在白名单内-X           |
      [输入]              |---------[取属性]                    [输出]
        |                              |-在白名单：相关判断处理-----|
        |--剩下的-escape------------------------------------------|
'''

from flask_restful import Resource,reqparse
from flask import render_template,make_response,render_template_string
xssparm=reqparse.RequestParser()
xssparm.add_argument('name',type=str,required=False,help='姓名')
xssparm.add_argument('type',type=str,required=False,help='xss类型')

class xss(Resource):
    def get(self):
        par=xssparm.parse_args()
        name=par.get('name','')
        type=par.get('type','')
        # 正确示例-1,内置函数自带输出编码
        if type=='safe_1':
            return make_response(render_template('xss.html',name=name))
        # 正确示例-2,内置函数{{}}自带输出编码
        elif type == 'safe_2':
            template = '''
            <html>
            <div>{{name}}</div>
            </html>
            '''
            return make_response(render_template_string(template, name=name))
        # 错误示例-1,内置函数{{}}自带输出编码,例外：style，javascript，onclick未手动escape；返回动态内容
        # http://0.0.0.0:8888/api/xss/?type=infected_1&name=alert(1)
        elif type=='infected_1':
            template = '''
            <html>
            <button onclick="javascript:{{name}}">{{type}}</button>
            </html>
            '''
            return make_response(render_template_string(template,type=type,name=name))
        # 错误示例-2,模版渲染拼接了用户可控内容，导致xss,http://0.0.0.0:8888/api/xss/?type=infected_2&name=<script>alert(1)</script>
        elif type=='infected_2':
            template = '''
                <html>
                <div>%s</div>
                </html>
                '''%(name)
            return make_response(render_template_string(template))
        else:
            return 404

