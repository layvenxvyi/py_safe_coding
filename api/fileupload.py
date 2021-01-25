#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2021-01-07 19:06
# @Author   :   layven
'''
-任意文件上传：任意文件上传是指服务端未对代码上传数据类型做控制，导致可执行代码上传到服务器上，若路径可控可访问则导致服务器被控制。
-利用：未限制文件大小，可能导致ddos，未限制文件后缀，导致任意文件上传，未给文件重命名，可能导致目录穿越，文件覆盖等问题。
-修复：1.校验文件类型，采用白名单控制，不在白名单之类的都抛出异常，如限制后缀ext在(‘png’,’jpg’)等；【必选】
      2.文件重命名，随机化命名能防止黑客猜测出文件路径；文件路径不接受参数控制，程序写死，且文件存放目录应设置没有执行权限；
      3.文件大小控制，这一步能防止上传大文件而导致的dos攻击；
-提供修复代码：
    1.判断文件类型方法，使用magic模块，需要安装python-magic
    2.判断文件大小方法
    3.判断存入的后缀是否在白名单内，再拼接随机命名为文件名，再进行存储
'''
from flask_restful import Resource,reqparse
from werkzeug.datastructures import FileStorage
from flask import render_template,make_response,jsonify,request
import magic,os,json,time

file_upload_parm=reqparse.RequestParser()
file_upload_parm.add_argument('imgFile',type=FileStorage,required=False,location='files',help="imgFile is wrong.")
file_upload_parm.add_argument('type',type=str,required=False,help='上传类型')

class file_upload(Resource):
    def get(self):
        return make_response(render_template('file_upload.html'))
    def post(self):
        try:
            par = file_upload_parm.parse_args()
            type=par.get('type','')
            #错误示例1-完全没有任何校验则上传文件
            if type=='infected-1':
                # 取文件内容也可以使用flask-request：imgFile= request.files['imgFile']
                imgFile = par.get('imgFile', '')
                imgFile.save(imgFile.filename)
                return make_response(render_template('file_upload.html'))
            #直接使用imgFile的content_type是前端传来的，可被篡改
            elif type=='infected-2':
                imgFile=par.get('imgFile', '')
                ct=imgFile.content_type
                allow_ct=["image/jpeg","image/png"]
                if ct in allow_ct:
                    imgFile.save(imgFile.filename)
                    return jsonify({"code": "file upload success!"})
                else:
                    return jsonify({"code": "illegal file"})
            #判断文件mime类型是否在白名单内，判断文件大小是否在限定内，再随机命名文件进行存储
            elif type=='safe':
                imgFile = par.get('imgFile', '')
                allow_suffix=['png','jpg','jpeg']
                sizejudge=self.filesize_judge(0.1,imgFile.read())
                mimejudge=self.ext_judge(allow_suffix,imgFile.read())
                if mimejudge and sizejudge:
                    #取后缀，后缀允许则随机命名存到路径下，以免文件名注入及猜测
                    suffix = imgFile.filename.split(".")[-1].lower() if "." in imgFile.filename else ''
                    if suffix and suffix in allow_suffix:
                        imgFile.save(str(int(time.time()))+"."+suffix)
                    else:
                        return jsonify({"code": "illegal file suffix!"})
                    return jsonify({"code": "file upload success!"})
                else:
                    return jsonify({"code": "illegal file"})
            else:
                return make_response(render_template('file_upload.html'))

        except Exception as e:
            return jsonify({"code": "异常", "message": "{}".format(e)})

    def filesize_judge(self,allow_size,file):
        #判断文件大小，传入allow_size为以MB为单位
        if (len(file)/(1024*1024))<allow_size:
            return True
        else:
            return False

    def ext_judge(self,secure_tag=[],file=''):
        # 使用magic.from_buffer进行文件的mime校验
        #以判断函数需输入允许的后缀列表，下标签供参考
        common_tag = {
            "image": ["png", "webp", "bmp", "gif", "jpg", "jpeg", "ico", "icon"],
            "package": ["rar", "zip", "ipa", "apk", "7z", "iso", "gz", "bz2", "pkg", "dmg", "tar"],
            "audio": ["wave", "mp3", "wma", "wav", "flac", "3gpp"],
            "video": ["mp4", "avi", "mov", "3gp", "rmvb", "flv", "mpeg", "mkv", "wmv", "mpv"],
            "font": ["ttf", "otf", "woff", "woff2", "eot"],
            "doc": ["rtf", "txt", "ini"]
        }
        dirname,filename = os.path.split(os.path.abspath(__file__))
        with open(dirname+"/config.py") as f:
            ext2mime = json.loads(f.readline())
        exttype=[]
        if secure_tag:
            for ext in secure_tag:
                for i in range(len(ext2mime[ext])):
                    if ext2mime[ext][i] not in exttype:
                        exttype.append(ext2mime[ext][i])
        try:mime = magic.from_buffer(file,mime=True)
        except:raise Exception('请传入文件')
        if mime in exttype:
            return True
        else:
            return False

