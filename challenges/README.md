# LilCTF 2025 赛题源代码及官方题解

## 目录结构

```plaintext
misc-example
├── 📁 assets: writeup 中的图片等资源文件
├── 📁 attachment: 附件，或构建容器后复制出附件的脚本
├── 📁 build: 容器构建
│   └── 🐳 Dockerfile
├── 📁 solve: exploit 脚本
├── 📁 src: 不用于容器构建的部分源代码
├── 📄 challenge.yaml: 题目的非段落类型数据
└── 📄 README.md: 题目描述、hints、部署注意事项、writeup
```

## 已构建镜像

LilCTF 所有容器题目通过 GitHub Actions 构建，每次代码 push 时自动触发构建，并推送到 GitHub 容器注册表和阿里云容器注册表（ACR）。现已在 ACR 上公开赛时使用的镜像，版本 tag 为 latest。

可在启动容器时传入 `LILCTF_FLAG` 或 `A1CTF_FLAG` 或 `GZCTF_FLAG` 或 `FLAG` 环境变量来设置容器的 flag。

```bash
docker pull 镜像地址
docker run -d -e 'FLAG=LILCTF{this_is_a_test_flag}' -p 宿主机端口:容器内端口 镜像地址
```

## 题目列表

| **#** | **文件夹名称**                                                  | **题目名称**               | **类别**     | **出题人**        | **难度** | **解出人数** | **最终分数** |
|-------|------------------------------------------------------------|------------------------|------------|----------------|--------|----------|----------|
| 1     | [blockchain-treasure](./blockchain-treasure)               | 生蚝的宝藏                  | Blockchain | shenghuo2      | 中等     | 18       | 484      |
| 2     | [crypto-baaaaaag](./crypto-baaaaaag)                       | baaaaaag               | Crypto     | pirater        | 中等     | 49       | 181      |
| 3     | [crypto-ez-math](./crypto-ez-math)                         | ez_math                | Crypto     | sudopacman     | 简单     | 353      | 50       |
| 4     | [crypto-linear](./crypto-linear)                           | Linear                 | Crypto     | 未央             | 中等     | 87       | 112      |
| 5     | [crypto-mid-math](./crypto-mid-math)                       | mid_math               | Crypto     | sudopacman     | 简单     | 202      | 50       |
| 6     | [crypto-space-travel](./crypto-space-travel)               | Space Travel           | Crypto     | 糖醋小鸡块          | 中等     | 39       | 234      |
| 7     | [misc-avatar](./misc-avatar)                               | v我50(R)MB              | Misc       | ZianTT, LilRan | 简单     | 84       | 114      |
| 8     | [misc-png-master](./misc-png-master)                       | PNG Master             | Misc       | YanHuoLG       | 简单     | 133      | 101      |
| 9     | [misc-public-ahead](./misc-public-ahead)                   | 提前放出附件                 | Misc       | C3ngH          | 简单     | 41       | 221      |
| 10    | [pwn-checkin](./pwn-checkin)                               | 签到                     | Pwn        | gets           | 签到     | 203      | 50       |
| 11    | [pwn-heap-pivoting](./pwn-heap-pivoting)                   | heap_Pivoting          | Pwn        | gets           | 简单     | 28       | 333      |
| 12    | [pwn-ilikecpp](./pwn-ilikecpp)                             | I like C 艹             | Pwn        | inkey          | 中等     | 7        | 766      |
| 13    | [pwn-kuroko](./pwn-kuroko)                                 | 白井黑子·风纪委               | Pwn        | kuroko         | 困难     | 0        | 1000     |
| 14    | [pwn-ret2all](./pwn-ret2all)                               | ret2all                | Pwn        | YX-hueimie     | 困难     | 4        | 874      |
| 15    | [pwn-trumanshow](./pwn-trumanshow)                         | The Truman Show        | Pwn        | c_lby          | 中等     | 18       | 484      |
| 16    | [re-arm-asm](./re-arm-asm)                                 | ARM ASM                | Reverse    | PangBai        | 简单     | 170      | 100      |
| 17    | [re-captcha](./re-captcha)                                 | 1'M no7 A rO6oT        | Reverse    | LilRan         | 简单     | 102      | 105      |
| 18    | [re-obfusheader](./re-obfusheader)                         | obfusheader.h          | Reverse    | LilRan         | 困难     | 50       | 177      |
| 19    | [re-oh-my-uboot](./re-oh-my-uboot)                         | Oh_My_Uboot            | Reverse    | PangBai        | 中等     | 28       | 333      |
| 20    | [re-qt-creator](./re-qt-creator)                           | Qt_Creator             | Reverse    | 晓梦ovo          | 简单     | 61       | 144      |
| 21    | [warmup-crypto-just-decrypt](./warmup-crypto-just-decrypt) | 对称！Just Decrypt        | Crypto     | Anonymous      | N/A    | 130      | 105      |
| 22    | [warmup-misc-questionnaire](./warmup-misc-questionnaire)   | 签到！真实世界的过期问卷           | Misc       | Anonymous      | N/A    | 81       | 136      |
| 23    | [warmup-pwn-kuroko](./warmup-pwn-kuroko)                   | 电击！白井黑子                | Pwn        | Anonymous      | N/A    | 5        | 866      |
| 24    | [warmup-re-pyarmor-mini](./warmup-re-pyarmor-mini)         | 纸老虎！真实世界的 Pyarmor Mini | Reverse    | Anonymous      | N/A    | 6        | 836      |
| 25    | [warmup-web-turboflash](./warmup-web-turboflash)           | 接力！TurboFlash          | Web        | Anonymous      | N/A    | 40       | 289      |
| 26    | [web-blade-cc](./web-blade-cc)                             | blade_cc               | Web        | N1ght          | 困难     | 5        | 836      |
| 27    | [web-ekko_exec](./web-ekko_exec)                           | Ekko_note              | Web        | LamentXU       | 简单     | 136      | 101      |
| 28    | [web-ez-bottle](./web-ez-bottle)                           | ez_bottle              | Web        | 0raN9e         | 简单     | 206      | 100      |
| 29    | [web-one-job](./web-one-job)                               | 我曾有一份工作                | Web        | 晨曦             | 中等     | 18       | 484      |
| 30    | [web-php_jail_is_my_cry](./web-php_jail_is_my_cry)         | php_jail_is_my_cry     | Web        | Kengwang       | 中等     | 10       | 673      |
| 31    | [web-your_uns3r](./web-your_uns3r)                         | Your Uns3r             | Web        | Kengwang       | 简单     | 75       | 122      |
