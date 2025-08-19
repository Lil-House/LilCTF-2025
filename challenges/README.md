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
