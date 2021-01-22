'''
-SQL注入是指原始SQL查询被动态更改成一个与程序预期完全不同的查询。执行这样一个更改后的查询可能导致信息泄露或者数据被篡改。
-防止SQL注入的方式主要可以分为两类：
    1 首选：参数化查询，如使用orm【思想：将sql与参数分开传入：execute(query,args)】；参考示例1/2/3/5
    2 次选：若存在特殊情况再使用转义特殊符号；参考示例4/6
-利用如下
    原始sql：SELECT * FROM Users WHERE Username='$username' AND Password='$password’
    用户提交参数：$username = 1‘ or ’1‘ = ’1；$password = 1' or '1' = '1
    执行sql：SELECT * FROM Users WHERE Username='1' OR '1' = '1' AND Password='1' OR '1' = '1'
'''


from flask_restful import Resource,reqparse
from models import db,Test,serialize
import pymysql
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import text
pymysql.install_as_MySQLdb()
sqlparm=reqparse.RequestParser()
sqlparm.add_argument('name',type=str,required=False,help='姓名')
sqlparm.add_argument('type',type=str,required=False,help='注入类型')

class sql_inject(Resource):
    def get(self):
        par=sqlparm.parse_args()
        name=par.get('name','')
        type=par.get('type','')
        conn = pymysql.connect(host='127.0.0.1', port=3306, user='threaten', passwd='threaten', db='threaten')
        cursor = conn.cursor()
        if type=='safe_orm1':
            # 正确示例1：以下使用sqlalchemy - orm方式，不会存在sql注入【首推荐】
            data = serialize(Test.query.filter(Test.name == name).all())
            return data
        elif type=='safe_orm2':
            # 正确示例2：sqlalchemy - orm方式，不会存在sql注入【首推荐】
            data = db.session.query(Test.name, Test.action).filter(Test.name==name)
        elif type=='safe_api1':
            # 正确示例3：api_orm使用预编译【首推荐】
            cursor.execute("select name,action from test where name=%s", (name))
            data = cursor.fetchall()
        elif type == 'safe_api2':
            # 正确示例4：内置函数转义特殊符号
            name = pymysql.escape_string(name)
            sql = "select name,action from test where name='%s'" % (name)
            cursor.execute(sql)
            data = cursor.fetchall()
        elif type=='safe_api3':
            # 正确示例5：name=:name为预编译模式【首推荐】
            stmt = text("SELECT name,action FROM test where name=:name")
            # query = db.session.query(Test.name, Test.action).from_statement(stmt).params(name=name)  # 用法1-使用db
            query=SQLAlchemy().session.query(Test.name, Test.action).from_statement(stmt).params(name=name) # 用法2-使用Test类
            data=query.all()
        elif type == 'safe_api4':
            # 正确示例6：自定义函数转义特殊符号
            name = self.safe_sql_escape(name)
            sql = "select name,action from test where name='%s'" % (name)
            cursor.execute(sql)
            data = cursor.fetchall()
        elif type=='notsafe_1':
            # 错误示例1：拼接用户输入，使用xx和xx' or '1'='1可验证
            sql = "select name,action from test where name='%s'" % (name)
            cursor.execute(sql)
            data = cursor.fetchall()
        elif type=='notsafe_2':
            # 错误示例2：拼接用户输入
            sql = "select name,action from test where name='" + name + "'"
            cursor.execute(sql)
            data = cursor.fetchall()
        elif type=='notsafe_3':
            # 错误示例3：拼接用户输入
            sql = "select name,action from test where name='{0}'".format(name)
            cursor.execute(sql)
            data = cursor.fetchall()
        elif type=='notsafe_4':
            # 错误示例4：拼接用户输入
            sql = f"select name,action from test where name='{name}'"
            cursor.execute(sql)
            data = cursor.fetchall()
        cursor.close()
        conn.close()
        return dict(data)

    def safe_sql_escape(self,param):
        if isinstance(param,str):
            param = param.replace('\\', '\\\\')
            param = param.replace("'", "\\\'")
            param = param.replace('"', '\\\"')
            return "{}".format(param)
        else:
            print('转义出现错误，请查看类型是否正确')
            return param
