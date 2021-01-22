#! /usr/bin/python
# -*-coding:utf-8 -*-
# @Time     :   2021-01-06 09:29
# @Author   :   layven
'''
-命令执行漏洞，就是指用户通过浏览器或其他辅助程序提交执行命令，由于服务器端没有针对执行函数做过滤，导致在没有指定绝对路径的情况下就执行命令。
-类型1：直接调用操作系统命令
    -危险函数：os.system,os.popen,os.spaw*,os.exec*,os.open,os.popen*,commands.call,commands.getoutput,Popen*
    -修复：
    1.不使用危险函数执行系统命令或不接受任何参数，使用subprocess，以列表形式传参，且shell不设置为true，默认为false[最佳][正确示例2]
    2.根据业务规则对格式长度类型进行限制及校验[次选][正确示例1]
    3.使用shlex过滤进行强校验[次次选][正确示例3]
-类型2：靠执行脚本代码调用操作系统命令
    -危险函数：eval，exec
    -修复：
    1.eval：不使用eval函数[正确示例4]；提供safe_eval方法替代eval方法[正确示例5]
    [该方法仅保留安全且使用较多的函数集合，此外通过代码构造抽象语法树（AST）检查节点的类型来限制可用的属性访问语句，针对白名单里未包含的属性访问语句使用了`ast.literal_eval`函数进行兜底，当都未执行成功会直接抛出异常。]
    2.不使用exec或者不接受参数调用
'''
from flask_restful import Resource,reqparse
from flask import render_template,make_response,jsonify
import os,urllib,subprocess,shlex,re,json
cmdparm=reqparse.RequestParser()
cmdparm.add_argument('filename',type=str,required=False,help='执行命令参数-系统命令执行')
cmdparm.add_argument('codeexec',type=str,required=False,help='执行命令参数-代码执行')
cmdparm.add_argument('type',type=str,required=False,help='ssrf类型')

class cmdexec(Resource):
    def get(self):
        par=cmdparm.parse_args()
        filename=par.get('filename','')
        codeexec=par.get('codeexec','')
        type=par.get('type','')
        try:
            filedir='/Users/xuwenfen/Desktop/safecoding/'
            # 错误示例-1,直接对前端传入的filename执行系统命令
            # 漏洞利用http://0.0.0.0:8888/api/cmdexec/?filename=test.txt;whoami&type=infected_1
            if type == 'infected_1':
                data=os.popen('cat '+filedir+filename).read()
            # 正确示例-1,对filename进行业务规则校验再执行命令
            elif type=='safe_1':
                filename_safe = re.match("^[a-zA-Z0-9]*\.txt$", filename)
                if filename_safe:
                    data=os.popen('cat '+filedir+filename_safe).read()
                else:
                    raise Exception("非法请求",filename)
            # 正确示例-2，使用subprocess以列表的方式传入参数
            elif type=='safe_2':
                data=str(subprocess.check_output(['cat',filedir+filename]))
            # 正确示例-3，使用shlex.quote()在字符串最外层加上单引号使字符串只能做为一个单一体出现，将字符串内的单引号用双引号引起来使其失去可能的闭合功能。
            elif type=='safe_3':
                filename_safe=shlex.quote(filename)
                print(filename_safe)
                data = os.popen('cat ' + filedir + filename_safe).read()
            # 错误示例-2，使用eval转换字符串为字典，列表等类型
            # 正常请求http://0.0.0.0:8888/api/cmdexec/?codeexec={"1":"a","2":"b"}&type=infected_2
            # 漏洞利用http://0.0.0.0:8888/api/cmdexec/?codeexec=__import__("os").system("pwd")&type=infected_2
            elif type=='infected_2':
                data=eval(codeexec)
            # 正确示例-4，如转换str为dic可用json替代
            elif type=='safe_4':
                data=json.loads(codeexec)
            elif type=='safe_5':
                data=safe_eval(codeexec)
            return {'data': data}
        except Exception as e:
            return jsonify({"code": "异常", "message": "{}".format(e)})

'''
以下safe_eval函数用于提供一种沙箱环境下的安全eval功能。
'''
import ast
import copy
from multiprocessing import Pool

def safe_eval(code, timeout=1):
    pool = Pool(processes=1)
    ret = pool.apply_async(run_eval, (code,))
    return ret.get(timeout=timeout)

def run_eval(code):
    ast_code = ast.parse(code)
    ASTSecurityChecker().visit(ast_code)
    SAFE_FUNCTIONS = {
        "max": max,
        "int": int,
        "str": str,
        "abs": abs,
        "ord": ord,
        "chr": chr,
        "hex": hex,
        "oct": oct,
        "sum": sum,
        "bin": bin,
        "divmod": divmod,
        "len": len,
        "min": min,
        "reversed": reversed
    }
    BASE_GLOBS = {
        "__builtins__": copy.deepcopy(SAFE_FUNCTIONS)
    }
    return eval(code, BASE_GLOBS)

class ASTSecurityChecker(ast.NodeVisitor):
    VISIT_WHITELIST = [
        "Call", "Name", "Module", "Expr", "Dict","Num", "BinOp", "Add", "Mult",
        "FloorDiv", "Div","Sub", "Tuple","Load", "NameConstant", "Str", "List"]
    def __getattr__(self, attr):
        if attr.startswith("visit_"):
            node_type = attr[len("visit_"):]
            if node_type not in self.VISIT_WHITELIST:
                raise Exception(node_type+"is not permitted")
            return getattr(super(ASTSecurityChecker, self), attr)