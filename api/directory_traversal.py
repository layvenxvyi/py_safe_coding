'''
-目录遍历/目录穿越/任意文件读取/任意文件下载是指通过绝对路径或者相对路径【使用../或者..\穿越上级目录】可控制读取/下载服务器上的文件。
-防御手段：1 路径不接受前端可控，只接受文件名可控，并对文件名做校验【长度、类型、语法以及业务规则】；
        2 路径接受可控在打开文件前需循环校验是否存在..字符，是则直接返回非法字符；
-提供修复代码：1.系统自带函数判断；2.flask自带函数判断；3.循环判断是否存在..字符
'''
from flask_restful import Resource,reqparse
from flask import jsonify,make_response,send_from_directory
import os
dirparm=reqparse.RequestParser()
dirparm.add_argument('filename',type=str,required=False,help='文件名')
dirparm.add_argument('type',type=str,required=False,help='目录类型')

class directory_traversal(Resource):
    def get(self):
        par=dirparm.parse_args()
        filename=par.get('filename','')
        type=par.get('type','')
        directory = '/Users/xuwenfen/Desktop/'

        # 错误示例-1：open函数直接读取用户输入可控的filename导致任意文件读取
        # http://0.0.0.0:8888/api/directory_traversal/?filename=../../../../etc/passwd&type=infected_dir1
        if type == 'infected_dir1':
            try:
                if os.path.isfile(directory + filename):
                    file = open(directory + filename)
                    response = file.read()
                    file.close()
                return make_response(response)
            except Exception as e:
                return jsonify({"code": "异常", "message": "{}".format(e)})

        #修复示例1：os.path.basename直接对文件名做处理，不允许文件名中出现目录结构
        elif type == 'repair_infected_dir1':
            try:
                if os.path.isfile(directory+os.path.basename(filename)):
                    file = open(directory+os.path.basename(filename))
                    response=file.read()
                    file.close()
                return make_response(response)
            except Exception as e:
                return jsonify({"code": "异常", "message": "{}".format(e)})

        # 安全示例-1：flask的send_from_directory函数处理filename是否包含目录结构，是则抛错
        elif type == 'safe_dir1':
            try:
                response = make_response(
                    send_from_directory(directory, filename, as_attachment=True))
                return response
            except Exception as e:
                return jsonify({"code": "异常", "message": "{}".format(e)})

        # 修复示例-1：使用目录穿越过滤器对输入进行判断，校验是否存在..非法字符
        elif type == 'dir_filter':
            try:
                filename=self.dir_filter(filename)
                if os.path.isfile(directory + filename):
                    file = open(directory + filename)
                    response = file.read()
                    file.close()
                return make_response(response)
            except Exception as e:
                return jsonify({"code": "异常", "message": "{}".format(e)})

    #目录穿越过滤器：判断是否存在..字符，默认存在则直接返回非法，可选择type='illegal_replace'对../替换为空处理
    # 注意：过滤器之后请不要重新对data进行解码，否则可使用编码方式绕过
    def dir_filter(self,data,type='illegal_notallow'):
        if isinstance(data,str):
            if type=='illegal_notallow':
                legal_data=True
                if '..' in data:
                    legal_data=False
                if legal_data:
                    return data
                else:
                    raise Exception("存在非法字符！",data)
            elif type=='illegal_replace':
                while True:
                    if '..' in data:data=data.replace('..','')
                    else:
                        return data
        else:
            raise Exception("请输入字符串类型进行判断！")





