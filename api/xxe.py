#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2021-01-20 18:44
# @Author   :   layven
'''
-XXE：简单来说，XXE就是XML外部实体注入。指当允许引用外部实体时，通过构造恶意内容，就可能导致任意文件读取、系统命令执行、内网端口探测、攻击内网网站等危害。
-防御：来禁用外部实体-resolve_entities=False
      禁止发起网络请求no_network=True,不设置会导致一些ssrf问题来将数据带出
【xml.dom.minidom,xml.etree.ElementTree不受影响】
'''
from flask import Flask, request, render_template,make_response
from flask_restful import Resource,reqparse
from lxml import etree
xxeparm=reqparse.RequestParser()
xxeparm.add_argument('xmlpayload',type=str,required=False,help='xml内容')
xxeparm.add_argument('type',type=str,required=False,help='类型')

USERNAME = 'admin' # 账号
PASSWORD = 'admin' # 密码

class xxe(Resource):
    def post(self):
        par=xxeparm.parse_args()
        xmlpayload=par.get('xmlpayload','')
        type=par.get('type','')
        try:
            # xmlpayload= "<user><username>admin</username><password>admin</password></user>"
            # xmlpayload='<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY  xxe SYSTEM "file:///etc/passwd" >]><user><username>&xxe;</username><password>admin</password></user>'
            if type=='safe':
                #设置2个参数，一个禁止外部实体，一个禁止发起网络请求
                tree = etree.fromstring(xmlpayload,etree.XMLParser(resolve_entities=False, no_network=True))
            else:
                tree = etree.fromstring(xmlpayload)  # 有漏洞
            for childa in tree:
                # print(childa.tag, childa.text, childa.attrib)
                if childa.tag == "username":
                    username = childa.text
                    print(username)
                if childa.tag == "password":
                    password = childa.text
                    print(password)
            if username == USERNAME and password == PASSWORD:
                result = "<result><code>%d</code><msg>%s</msg></result>" % (1, username)
            else:
                result = "<result><code>%d</code><msg>%s</msg></result>" % (0, username)
        except Exception as Ex:
            result = "<result><code>%d</code><msg>%s</msg></result>" % (3, str(Ex))
        return result, {'Content-Type': 'text/xml;charset=UTF-8'}
