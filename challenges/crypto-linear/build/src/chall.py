import os
import random
import signal

signal.alarm(10)

flag = os.getenv("LILCTF_FLAG", "LILCTF{default}")

nrows = 16
ncols = 32

A = [[random.randint(1, 1919810) for _ in range(ncols)] for _ in range(nrows)]
x = [random.randint(1, 114514) for _ in range(ncols)]

b = [sum(A[i][j] * x[j] for j in range(ncols)) for i in range(nrows)]
print(A)
print(b)

xx = list(map(int, input("Enter your solution: ").strip().split()))
if xx != x:
    print("Oh, your linear algebra needs to be practiced.")
else:
    print("Bravo! Here is your flag:")
    print(flag)
