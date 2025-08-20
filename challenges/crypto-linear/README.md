# Linear

**出题**：未央

**难度**：中等

## 题目描述

Just solving a system of equations.

## Writeup

出题的时候是从解法倒推题目，大概也能猜到有更简单的解法，就只卡了一下时间。

提供一个思路，解法不唯一：

首先题目给出的关系是

$$
Ax = b
$$

那么 $Ax$ 的左核就是 $b$ 的左核，即 $\ker(Ax)=\ker(b)$，那么 $\ker(b)Ax = O$，这样 $x$ 就存在于 $\ker(b)A$ 的右核中，$x$ 又特别小，所以做个 LLL 就出来了。

```python
from pwn import *
from sage.all import *

conn = process(["python3", "task.py"])
A = eval(conn.recvline().decode().strip())
b = eval(conn.recvline().decode().strip())

A = Matrix(ZZ, A)
b = Matrix(ZZ, b).T

ker_b = b.kernel().basis_matrix()
A = ker_b*A
ker_A = A.transpose().kernel().basis_matrix()
ker_A = ker_A.LLL()

solution = [abs(int(i)) for i in ker_A[0]]
conn.sendline(' '.join(map(str, solution)).encode())
conn.recvline()
flag = conn.recvline().decode('utf-8').strip()
print(flag)

conn.close()
```
