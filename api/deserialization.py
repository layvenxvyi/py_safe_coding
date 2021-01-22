#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2021-01-21 17:21
# @Author   :   layven
'''
-反序列化漏洞：
-防御：1.pickle改为json，yaml[使用5.1版本以上+使用SafeLoader]；2.反序列化对象不接受可控数据；3.对反序列化数据进行签名校验；
-出现场景：在解析认证token，session的时候；将对象Pickle后存储成磁盘文件；将对象Pickle后在网络中传输。
-危险函数：pickle.load(s)/cPickle.load(s)/yaml

-参考：https://rules.sonarsource.com/python/type/Vulnerability/RSPEC-5135

'''
from flask_restful import Resource,reqparse
from flask import jsonify
import pickle,os,yaml,json
serialparm=reqparse.RequestParser()
serialparm.add_argument('payload',type=str,required=False,help='反序列化payload')
serialparm.add_argument('type',type=str,required=False,help='反序列化类型')

class deserialization(Resource):
    def get(self):
        par=serialparm.parse_args()
        payload=par.get('payload','')
        type=par.get('type','')
        try:
            # 错误示例-1,直接使用pick反序列化不可信数据
            if type=='pick_infected':
            #请求url：http://0.0.0.0:8888/api/deserialization/?payload=\x80\x03cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'&type=pick_infected
                payload_byte=bytes(payload, encoding = "utf-8")
                import codecs
                payload_tuple = codecs.escape_decode(payload_byte, "hex-escape")
                return {"code": 200, "message": "{}".format(pickle.loads(payload_tuple[0]))}
            # 正确示例-1,直接使用json替代pick，json库为安全库
            if type=='pick_safe':
                return {"code": 200, "message": "{}".format(json.loads(payload))}
            # 错误示例-2,yaml[>5.1]设置加载模式为UnsafeLoader，或者使用5.1版本以下的都存在问题
            if type=='yaml_infected':
            #请求url：http://0.0.0.0:8888/api/deserialization/?payload=%21%21python%2Fobject%2Fnew%3Aos.system+%5B%22whoami%22%5D&type=yaml_infected
                return {"code": 200, "message": "{}".format(yaml.load(payload,Loader=yaml.UnsafeLoader))}
            # 正确示例-2,yaml[>5.1]设置加载模式为SafeLoader来序列化不可信数据
            if type=='yaml_safe':
                return {"code": 200, "message": "{}".format(yaml.load(payload,Loader=yaml.SafeLoader))}
        except Exception as e:
            return jsonify({"code": "异常", "message": "{}".format(e)})


class payload_gen_pickle(object):
    def __reduce__(self):
    #reduce是一个二元操作函数，第一个参数是函数名，第二个参数是第一个函数的参数数据结构，当类继承基础类object时候才会把这个函数内容序列化，所以反序列化时候才会导致漏洞
        return (os.system,('whoami',))
# a=payload_gen_pickle()
# payload=pickle.dumps(a)
#或者直接 payload=b'\x80\x03cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'

class payload_gen_yaml():
    def __init__(self):
        os.system('whoami')
# payload=yaml.dump(payload_gen_yaml())
# fp=open('test.yml','w')
# fp.write(payload)
#或者直接网上找payload打如 payload='!!python/object/new:os.system ["whoami"]'

