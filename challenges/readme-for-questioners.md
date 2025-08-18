# LilCTF 2025 内部仓库

这个仓库仅供赛前内部使用，永远不会直接公开。

需要构建 Docker 镜像的题目在此仓库管理。其他题目也可以放在这里，看你喜欢。

`snapshot` 分支中已有题目皆可作为范例，你可以复制一份去改。

**每一道题使用一个完全独立的分支**，总是基于主分支、但不需要向主分支发起 pull request。合并由 LilRan 适时进行，你无需关心。**每次在编辑前记得检查一下分支有没有切对**。

新建一道题目时，建议 checkout 到 snapshot，然后使用以下命令创建你的题目分支：

```bash
git branch 你的分支名
git switch 你的分支名
```

然后你就可以在这个分支里随意 commit 了。我们很 flex 的，除了下面的要求，你可以在自己的分支上随便放东西。

**你应该在 `.github` 文件夹放一个用于在 push 时自动构建 Docker 镜像的配置文件，建议复制 `!challenge-example.yml` 去改**。在你的分支第一次 push 前，务必把所有带 `CHANGE_ME` 字样的地方改掉。

不要忘记 push，将最新的修改同步到远程仓库。

**LilRan 可能会在你的分支修改你的题目文件，每次你在本地开始工作前，请先 `git pull`，确保你的分支是最新的。**

## 要求

- 分支名为方向和题目简称，只包含小写字母、数字、中划线，例如 `pwn-kuroko`。
- 不要在 challenges 文件夹之外放任何文件（你正在读的这一份 README.md 除外）。建一个与分支同名的文件夹，所有的文件（包括 `.gitignore` 之类，如果你需要的话）都放在这个文件夹里。
- 除非得到允许，否则不要从任何其他分支 merge 到你的分支。允许 rebase, squash, cherry-pick，但一般情况下每个分支完全独立，不需要做任何合并操作。
- 不要在仓库里存放大于 10MB 的文件，确有必要请提前获得允许。
- Docker 容器注入 flag 的环境变量需要与现有题目保持一致（兼容 `A1CTF_FLAG`、`LILCTF_FLAG`、`GZCTF_FLAG`、`FLAG`），以便已构建镜像赛后可以在多种复现平台上直接使用。

## 建议

以下内容把 snapshot 中已有题目的复制去改一下。

- 使用 https://github.com/GZCTF/challenge-base 作为基础镜像，用于简化启动过程的编写，并在不同题目间共用镜像层。（已经出好的用其他基础镜像的题目可以不改。）
- 在题目文件夹中放一个 `README.md`，写明部署信息和其他需要说明的内容。
- 编译产生的二进制文件除非很有必要，否则不要放在仓库里。用 `.gitignore` 忽略掉它们。
- 推荐在 workflow 中作为 artifact 上传：由构建镜像产生的发给选手的附件，例如编译的二进制文件以及 libc 之类的文件，以便附件与远程环境完全相同。
- 不需要换国内源（因为是用 GitHub 托管的 Action runner 来 build 的）

## 拉镜像

- https://github.com/settings/tokens/new 给自己的 GitHub 账号创建一个 Personal access token，权限选择 `read:packages`，保存好 token。
- `docker login ghcr.io -u <你的 GitHub 账号> -p <你的 token>`，登录到 GitHub 的 Docker registry。
- `docker pull ghcr.io/lil-ran/lilctf-2025-internal/xxx:latest`
- 自己在本地测的时候，`docker run -d -e '环境变量名=LILCTF{this_is_a_test_flag}' -p 宿主机端口:容器内端口 ghcr.io/lil-ran/lilctf-2025-internal/容器名`

## 运行日志、附件

https://github.com/Lil-Ran/LilCTF-2025-INTERNAL/actions
