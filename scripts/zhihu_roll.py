import os
import random


random.seed(os.urandom(16))

# 按时间顺序，由新到旧
users = [
    "Reimu Hakurei",
    "xinghe123",
    "Zyyyy",
    "Ha_1lt0n",
    "开心上早八",
    "self-knowledge",
    "Superseller",
    "青峥",
    "远方",
    "伤星",
    "candlest",
    "LamentXU",
    "世界无限炎斬者",
    "gets",
    "陈平安",
    "油炸战斧洋芋",
    "放开挪腻我来",
    "Cyyyy.",
    "樱桃奶球",
    "凌晨",
    "Naby",
    "C3ngH",
    "Alexander",
    "你以为你说的话我",
    "江南不会是",
    "endowment",
    "知乎用户5GKNFK",
    "选电脑好难",
    "Matrix",
    "Lucifrix",
    "SfTian",
]

print("🎉", random.sample(users, k=5))
