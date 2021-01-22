#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2020-12-21 18:29
# @Author   :   layven
from flask_restful import Api
from api.sql_inject import sql_inject
from api.xss import xss
from api.directory_traversal import directory_traversal
from api.ssrf import ssrf
from api.cmdexec import cmdexec
from api.fileupload import file_upload
from api.csrf import csrf
from api.xxe import xxe
from api.deserialization import deserialization


api=Api()

def init_api(app):
    api.init_app(app)


api.add_resource(sql_inject,'/api/sql_inject/')#sql注入
api.add_resource(xss,'/api/xss/')#xss跨站脚本攻击
api.add_resource(directory_traversal,'/api/directory_traversal/')#目录遍历/目录穿越/任意文件读取/任意文件下载
api.add_resource(ssrf,'/api/ssrf/')#ssrf服务端请求伪造
api.add_resource(cmdexec,'/api/cmdexec/')#命令执行/注入
api.add_resource(file_upload,'/api/file_upload/')#文件上传
api.add_resource(csrf,'/api/csrf/')#csrf跨域请求伪造
api.add_resource(xxe,'/api/xxe/')#xxe-xml注入
api.add_resource(deserialization,'/api/deserialization/')#反序列化漏洞




