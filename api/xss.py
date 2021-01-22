'''
-XSS俗称跨站脚本攻击，是指攻击者通过”HTML注入”篡改网页，插入恶意脚本，从而在用户浏览网页时控制用户浏览器，危害：窃取cookie、放蠕虫、网站钓鱼等
-防护：宁死也不让数据变成可执行的代码，不信任任何用户的数据，严格区分数据和代码。
    2.输出编码：哪里有漏洞则在哪里对返回进行html实体编码
    注意：应用程序对同一输入不做两次解码，否则容易使用多次编码进行绕过；过滤器应防护多种请求格式，get/post/multipart
-提供修复代码：html富文本过滤器
    1.使用方法:html=XSSFilter(html[,write_dict]).safe_process()，其中write_dict为可添加的自定义白名单字典【k:v】对应【标签:属性列表】，当输入的write_dict中的标签在XSSFilter已经存在时，其属性值会覆盖XSSFilter对应的标签的属性列表。
    2.过滤器思路：
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
        # 修复示例：使用html富文本过滤器处理输入,白名单标签及属性
        elif type == 'xss_filter':
            name=XSSFilter(name).safe_process()
            template = '''
                <html>
                <div>%s</div>
                </html>
                ''' % (name)
            return make_response(render_template_string(template))
        else:
            return 404

'''过滤器开始'''
try:
    from urllib import parse
except ImportError:
    import urllib as parse
import re
class XSSFilter():
    """ 对比github上fork最多的【https://github.com/phith0n/python-xss-filter/blob/master/pxfilter.py】
     github白名单机制缺点：把标签和属性分开，可自行编辑代码修改白名单，不支持参数方式引入，若是增加属性白名单则会为作用于所有标签
     此过滤器则使用标签和属性对应的白名单机制，且支持参数方式引入，最小范围影响白名单，以免误杀业务也免被漏洞绕过 """
    defaultAllowList = {
        "a": ["target", "href", "title", "class"],
        "abbr": ["title", "class"],
        "address": ["class"],
        "area": ["shape", "coords", "href", "alt", "class"],
        "article": ["class"],
        "aside": ["class"],
        "audio": ["autoplay", "controls", "loop", "preload", "src", "class"],
        "b": ["class"],
        "bdi": ["dir", "class"],
        "bdo": ["dir", "class"],
        "big": ["class"],
        "blockquote": ["cite", "class"],
        "br": ["class"],
        "caption": ["class"],
        "center": ["class"],
        "cite": ["class"],
        "code": ["class"],
        "col": ["align", "valign", "span", "width", "class"],
        "colgroup": ["align", "valign", "span", "width", "class"],
        "dd": ["class"],
        "del": ["datetime", "class"],
        "details": ["open", "class"],
        "div": ["class"],
        "dl": ["class"],
        "dt": ["class"],
        "em": ["class"],
        "font": ["color", "size", "face", "class"],
        "footer": ["class"],
        "h1": ["class"],
        "h2": ["class"],
        "h3": ["class"],
        "h4": ["class"],
        "h5": ["class"],
        "h6": ["class"],
        "header": ["class"],
        "hr": ["class"],
        "i": ["class"],
        "img": ["src", "alt", "title", "width", "height", "class"],
        "ins": ["datetime", "class"],
        "li": ["class"],
        "mark": ["class"],
        "nav": ["class"],
        "ol": ["class"],
        "p": ["class"],
        "pre": ["class"],
        "s": ["class"],
        "section": ["class"],
        "small": ["class"],
        "span": ["class"],
        "sub": ["class"],
        "sup": ["class"],
        "strong": ["class"],
        "table": ["width", "border", "align", "valign", "class"],
        "tbody": ["align", "valign", "class"],
        "td": ["width", "rowspan", "colspan", "align", "valign", "class"],
        "tfoot": ["align", "valign", "class"],
        "th": ["width", "rowspan", "colspan", "align", "valign", "class"],
        "thead": ["align", "valign", "class"],
        "tr": ["rowspan", "align", "valign", "class"],
        "tt": ["class"],
        "u": ["class"],
        "ul": ["class"],
        "video": ["autoplay", "controls", "loop", "preload", "src", "height", "width", "class"]
        }
    REGEXP_LT = "<"
    REGEXP_GT = ">"
    REGEXP_QUOTE = "\""
    REGEXP_QUOTE_2 = "&quot;"
    REGEXP_ATTR_VALUE_1 = re.compile(r"&#([a-zA-Z0-9]*);?", flags=re.IGNORECASE)
    REGEXP_ATTR_VALUE_COLON = re.compile(r"&colon;?", flags=re.IGNORECASE)
    REGEXP_ATTR_VALUE_NEWLINE = re.compile(r"&newline;?", flags=re.IGNORECASE)
    REGEXP_ATTR_VALUE_TAB = re.compile(r"&tab;?", flags=re.IGNORECASE)
    REGEXP_ATTR_VALUE_SOL = re.compile(r"&sol;?", flags=re.IGNORECASE)
    REGEXP_ATTR_VALUE_SNT = re.compile(r"\s|\n|\t")
    REGEXP_ILLEGAL_ATTR_NAME = re.compile(r"[^a-zA-Z0-9_:\.\-]", flags=re.IGNORECASE)
    def __init__(self, html, allowlist=None):
        self.html = html
        if allowlist:
            for tag, attr in allowlist.items():
                self.defaultAllowList.update({tag: attr})
    def escape_quote(self, html):#引号实体编码
        return html.replace(self.REGEXP_QUOTE, "&quot;")
    def escape_htmlentities(self, html):#找到输入中存在的实体编码，进行逆实体编码
        def replace_unicode(match):
            match = match.group()
            if len(match) > 50:
                return ""
            if match[-1] != ";":
                match = match + ";"
            try:
                return chr(int(match[3:-1], 16)) if match[2].lower() == "x" else chr(int(match[2:-1]))
            except Exception:
                return ""
        ret = self.REGEXP_ATTR_VALUE_1.sub(replace_unicode, html)
        if len(self.REGEXP_ATTR_VALUE_1.findall(ret)):
            return self.escape_htmlentities(ret)
        return ret
    def escape_danger_html5entities(self, html):#逆实体编码为危险符号，以备后续处理
        html = self.REGEXP_ATTR_VALUE_COLON.sub(":", html)
        html = self.REGEXP_ATTR_VALUE_NEWLINE.sub(" ", html)
        html = self.REGEXP_ATTR_VALUE_SOL.sub("/", html)
        html = self.REGEXP_ATTR_VALUE_TAB.sub(" ", html)
        return html
    def is_closing(self, html):#判断标签是否结束
        return html[:2] == "</"
    def safe_process(self):#主函数
        try:
            ret_html = self.parse_tag(self.html)#处理逻辑开始
        except Exception:
            ret_html = ""
        return ret_html
    def escape_html(self, html):#实体编码<>
        return html.replace(self.REGEXP_LT, "&lt;").replace(self.REGEXP_GT, "&gt;")
    def unescape_quote(self, html):
        return html.replace(self.REGEXP_QUOTE_2, "\"")
    def clear_nonprintable_character(self, html):#处理ascii中的不可显示字符
        str1 = ""
        for c in html:
            str1 = str1 + " " if ord(c) < 32 else str1 + c
        return str1.strip()
    def safe_attrvalue(self, name, value):
        """ 逆参数中的实体编码，去除ascii中的不可显示字符，作用：很多xss编码绕过的变体可通过此识别并干掉 """
        value = self.unescape_quote(value)
        value = self.escape_htmlentities(value)
        value = self.escape_danger_html5entities(value)
        value = self.clear_nonprintable_character(value)
        """ 单独处理href和src属性 """
        if name in ["src", "href"]:
            value = value.strip()
            if len(value) and value[0] in ["#", "/", "?"]:
                # 对双引号进行一次编码，防止非预期
                return value.replace("\"", "%22")
            tmp_value = ""
            for c in value:
                if ord(c) > 32 and ord(c) < 127:
                    tmp_value += c
            if tmp_value[:11].lower() == "javascript:":
                return ""
            if tmp_value[:14].lower() == "data:text/html":
                return ""
            """ 对协议出现ﬀ这类可代表2个字符的unicode进行url编码 """
            splitslash = value.split("/")
            splitmao = splitslash[0].split(":")[0]
            tmp_value = ""
            for c in splitmao:
                if ord(c) > 32 and ord(c) < 127:
                    tmp_value += c
                else:
                    tmp_value += parse.quote(c)
            value = tmp_value.replace("&", "&amp;") + value[len(splitmao):]
        value = self.escape_quote(value)
        value = self.escape_html(value)
        return value
    def on_attr(self, name, value, tag):#判断标签的属性是否为白名单，非白干掉，白继续处理
        is_allow_attr = name in self.defaultAllowList[tag]
        if is_allow_attr:
            value = self.safe_attrvalue(name, value)
            if value:
                return name + '="' + value + '"'
            else:
                return name
        return None
    def on_tag(self, source_position, position, tag, html, is_closing):#对标签进行判断，非白干掉，白则取属性继续判断
        info = {
            "sourcePosition": source_position,
            "position": position,
            "is_closing": is_closing,
            "isAllow": tag in self.defaultAllowList
        }
        if info["isAllow"]:
            if info["is_closing"]:
                return "</" + tag + ">"
            attrs = self.get_attrs(html)
            try:
                attrs_html = self.parse_attr(attrs["html"], tag)
            except Exception:
                attrs_html = ""
            html = "<" + tag
            if attrs_html:
                html += " " + attrs_html
            if attrs["closing"]:
                html += " /"
            html += ">"
            return html
        else:
            return self.escape_html(html)
    def get_attrs(self, html):#取属性值
        if " " not in html:
            return {
                "html": "",
                "closing": html[-2] == "/"
            }
        i = html.index(" ")
        html = html[i+1:-1].strip()
        if not len(html):
            return {
                "html": "",
                "closing": False
            }
        is_closing = html[-1] == "/"
        if is_closing:
            html = html[:-1].strip()
        return {
            "html": html,
            "closing": is_closing
        }
    def get_tagname(self, html):#取标签名
        if " " not in html:
            tag = html[1:-1]
        else:
            tag = html[1:html.index(" ")]
        tag = tag.lower().strip()
        if not len(tag):
            return False
        if tag[0] == "/":
            tag = tag[1:]
        elif tag[-1] == "/":
            tag = tag[:-1]
        return tag
    def parse_tag(self, html):#识别输入中的标签【继续判断标签】+剩余【直接escape】
        rethtml = ""
        tag_start = False
        quote_start = False
        last_pos = 0
        for current_pos in range(len(html)):
            if str(tag_start) == "False":
                if html[current_pos] == "<":
                    tag_start = current_pos
                    continue
            else:
                if not quote_start:
                    if html[current_pos] == "<":
                        rethtml += self.escape_html(html[last_pos:current_pos])
                        tag_start = current_pos
                        last_pos = current_pos
                        continue
                    if html[current_pos] == ">":
                        rethtml += self.escape_html(html[last_pos:tag_start])
                        current_html = html[tag_start:current_pos+1]
                        current_tag = self.get_tagname(current_html)
                        rethtml += self.on_tag(tag_start, len(rethtml), current_tag,
                                               current_html, self.is_closing(current_html))
                        last_pos = current_pos + 1
                        tag_start = False
                    if (html[current_pos] == "\"" or html[current_pos] == "'") and html[current_pos-1] == "=":
                        quote_start = html[current_pos]
                        continue
                else:
                    if html[current_pos] == quote_start:
                        quote_start = False
                        continue
        if last_pos < len(html):
            rethtml += self.escape_html(html[last_pos:])
        return rethtml
    def parse_attr(self, html, tag):#识别上端处理后中的属性【继续判断属性】
        last_pos = 0
        ret_attrs = []
        tmp_name = False
        def add_attr(name, value, tag):
            name = name.strip()
            name = self.REGEXP_ILLEGAL_ATTR_NAME.sub("", name).lower()
            if not len(name):
                return
            ret = self.on_attr(name, value, tag)
            if ret:
                ret_attrs.append(ret)
        i = 0
        while i < len(html):
            if not tmp_name and html[i] == "=":
                tmp_name = html[last_pos:i]
                i += 1
                if i == len(html):
                    if tmp_name:
                        add_attr(tmp_name, "", tag)
                        last_pos = i
                    break
                while html[i] == " ":
                    i += 1
                last_pos = i
                continue
            if tmp_name:
                is_equal = False
                j = i - 1
                while j > 0:
                    if html[j] == " ":
                        j -= 1
                        continue
                    if html[j] == "=":
                        is_equal = True
                    break
                if i == last_pos and (html[i] == "\"" or html[i] == "'") and is_equal:
                    if html[i] not in html[i+1:]:
                        break
                    else:
                        tmp_value = html[last_pos + 1: i+1+html[i+1:].index(html[i])]
                        add_attr(tmp_name, tmp_value, tag)
                        tmp_name = False
                        i = i+1+html[i+1:].index(html[i])
                        last_pos = i + 1
                        i += 1
                        continue
            if self.REGEXP_ATTR_VALUE_SNT.match(html[i]):
                html = self.REGEXP_ATTR_VALUE_SNT.sub(" ", html)
                if not tmp_name:
                    j, tmp = self.find_next_equal(html, i)
                    if j == -1:
                        add_attr(html[last_pos: i], "", tag)
                        tmp_name = False
                        last_pos = i + 1
                        i += 1
                        continue
                    else:
                        i = tmp
                        continue
                else:
                    j = self.find_before_equal(html, i - 1)
                    if j == -1:
                        tmp_value = html[last_pos:i].strip()
                        add_attr(tmp_name, tmp_value, tag)
                        tmp_name = False
                        last_pos = i + 1
                        i += 1
                        continue
                    else:
                        i += 1
                        continue
            i += 1
        if last_pos < len(html):
            if not tmp_name:
                add_attr(html[last_pos:], "", tag)
            else:
                add_attr(tmp_name, self.strip_quotewrap(html[last_pos:].strip()), tag)
        return " " .join(ret_attrs).strip()
    def strip_quotewrap(self, text):
        if (text[0] == "\"" and text[-1] == "\"") \
                or (text[0] == "'" and text[-1] == "'"):
            return text[1: -1]
        else:
            return text
    def find_before_equal(self, html, i):
        while i > 0:
            if html[i] == " ":
                i -= 1
                continue
            if html[i] == "=":
                return i
            return -1
    def find_next_equal(self, html, i):
        while i < len(html):
            if html[i] == " ":
                i += 1
                continue
            if html[i] == "=":
                return 1, i
            return -1, i
'''过滤器结束'''