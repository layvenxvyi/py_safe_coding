#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2020-12-25 10:17
# @Author   :   layven
'''
-SSRF服务端请求伪造攻击，是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。
（正是因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内部系统）。
-漏洞原因：由于服务端提供了从其他服务器获取数据的功能且没有对目标地址做过滤和限制，使用Requests，Pycurl，Urllib等但未校验都存在问题
        【Requests和pycurl能识别http://127.0.0.1@192.168.3.3为192.168.3.3，urllib2直接报错】
-危害：对外网、内网、本地进行端口扫描；攻击内外及本地主机如ssrf+redis/mongodb/s2；使用file/ftp协议读取本地文件。
-防护:1.优先选择使用白名单方式进行校验【如必须https://*.aaa.com/*.png】
     2.无法使用白名单方式提供ssrf过滤器【重点在于如何获取真正的请求地址】
        -过滤器修复思路：
        1.解析目标URL，获取其Host【考虑非http协议请求攻击】
        2.解析Host，获取Host指向的IP地址【考虑域名重绑定攻击，考虑特殊写法获取不到真正ip】
        3.检查IP地址是否为内网IP【考虑（八|十|十六）进制/ip省略写法绕过攻击】
        4.请求从URL获取到的IP
        5.如果有跳转，拿出跳转URL，执行1【考虑302跳转的攻击】
-参考：https://www.leavesongs.com/PYTHON/defend-ssrf-vulnerable-in-python.html
'''
from flask_restful import Resource,reqparse
from flask import render_template,make_response,jsonify
import urllib.request,base64,ssl
ssl._create_default_https_context = ssl._create_stdlib_context
ssrfparm=reqparse.RequestParser()
ssrfparm.add_argument('url',type=str,required=False,help='请求的url地址')
ssrfparm.add_argument('type',type=str,required=False,help='ssrf类型')

class ssrf(Resource):
    def get(self):
        par=ssrfparm.parse_args()
        url=par.get('url','')
        type=par.get('type','')
        # 正常请求http://0.0.0.0:8888/api/ssrf/?url=https://www.t00ls.net/static/images/logo.png&type=infected_1
        # 漏洞利用http://0.0.0.0:8888/api/ssrf/?url=file:///etc/passwd&type=infected_1，文件再base64解码回去即可
        try:
            # 错误示例-1,直接对前端传入的url进行请求
            if type=='infected_1':
                res=urllib.request.urlopen(url).read()
                img_stream = base64.b64encode(res).decode()
                return make_response(render_template('ssrf.html',res=img_stream))
            # 修复示例-1,对前端传入的url进行白名单校验，正则匹配白名单域名做防御【http(s)://www.*.qq.com/*.(png|jpg|jpeg)】
            if type=='white_list1':
                reurl = re.match("^http(s)?://www.[a-zA-Z0-9./-]*\.qq.com/[a-zA-Z0-9]*\.(jp(e)?g|png)$", url)
                if reurl:
                    res=urllib.request.urlopen(reurl).read()
                    img_stream=base64.b64encode(res).decode()
                    return make_response(render_template('ssrf.html',res=img_stream))
                else:
                    raise Exception("非法请求",url)
            # 修复示例-2,对前端传入的url进行白名单校验，使用urllib取请求的hostname
            if type=='white_list2':
                DOMAINS_WHITELIST = ['domain1.com', 'domain2.com']
                if urllib.parse.urlparse(url).hostname in DOMAINS_WHITELIST:
                    res = urllib.request.urlopen(url).read()
                    img_stream = base64.b64encode(res).decode()
                    return make_response(render_template('ssrf.html', res=img_stream))
            # 修复示例-3,无法使用白名单进行防御时，使用ssrf过滤器，检查请求目标，再执行请求
            #http://0.0.0.0:8888/api/ssrf/?url=https://www.leavesongs.com/content/uploadfile/201609/thum-15651475220446.png&type=ssrf_filter
            #http://0.0.0.0:8888/api/ssrf/?url=https://127.0.0.1&type=ssrf_filter
            if type == 'ssrf_filter':
                safeurl=ssrf_filter().safe_request_url(url)
                res = urllib.request.urlopen(safeurl).read()
                img_stream = base64.b64encode(res).decode()
                return make_response(render_template('ssrf.html', res=img_stream))
            else:
                return 404
        except urllib.error.URLError as e:
            return jsonify({"code": "异常", "message": "{}".format(e)})

import socket
import re,urljoin
import requests
from urllib.parse import urlparse
from socket import inet_aton
from struct import unpack
from requests.utils import requote_uri

class ssrf_filter(object):
    def __init__(self):
        pass

    def check_ssrf(self,url):
        # 获取请求的host
        hostname = urlparse(url).hostname

        # ip地址转换为整数
        def ip2long(ip_addr):
            return unpack("!L", inet_aton(ip_addr))[0]

        def is_inner_ipaddress(ip):
            ip = ip2long(ip)
            return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
                   ip2long('10.0.0.0') >> 24 == ip >> 24 or \
                   ip2long('172.16.0.0') >> 16 == ip >> 16 or \
                   ip2long('192.168.0.0') >> 16 == ip >> 16 or \
                   ip2long('0.0.0.0') >> 24 == ip >> 24

        try:
        # 只允许http请求，防止file及ftp等其他协议攻击
            if not re.match(r"^http(s)?://*", url):
                raise BaseException("url format error")
            #根据host取真正的ip地址
            ip_address = socket.getaddrinfo(hostname, 'http')[0][4][0]
            #判断ip地址是否内网地址
            if is_inner_ipaddress(ip_address):
                raise BaseException("inner ip address attack")
            return ip_address,hostname, "success"
        except BaseException as e:
            return False,False, str(e)
        except:
            return False,False,"unknow error"

    def safe_request_url(self,url, **kwargs):
        # 对存在30X跳转的做校验
        def _request_check_location(r, *args, **kwargs):
            if not r.is_redirect:
                return
            url = r.headers['location']

            # The scheme should be lower case...
            parsed = urlparse(url)
            url = parsed.geturl()

            # Facilitate relative 'location' headers, as allowed by RFC 7231.
            # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
            # Compliant with RFC3986, we percent encode the url.
            if not parsed.netloc:
                url = urljoin(r.url, requote_uri(url))
            else:
                url = requote_uri(url)

            ip,hostname,errstr = self.check_ssrf(url)
            if not ip:
                raise requests.exceptions.InvalidURL("SSRF Attack: %s" % (errstr,))

        ip,hostname,errstr = self.check_ssrf(url)
        if not ip:
            raise requests.exceptions.InvalidURL("SSRF Attack: %s" % (errstr,))

        all_hooks = kwargs.get('hooks', dict())
        if 'response' in all_hooks:
            if hasattr(all_hooks['response'], '__call__'):
                r_hooks = [all_hooks['response']]
            else:
                r_hooks = all_hooks['response']

            r_hooks.append(_request_check_location)
        else:
            r_hooks = [_request_check_location]

        all_hooks['response'] = r_hooks
        kwargs['hooks'] = all_hooks
        safe_url=url.replace(hostname,ip)
        # print(safe_url)
        return safe_url