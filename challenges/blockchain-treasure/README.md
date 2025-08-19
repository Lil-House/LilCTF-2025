# 生蚝的宝藏

**出题**：shenghuo2

**难度**：中等

## 题目描述

>传说中的*mega生蚝*，「世恩·G·赫奥·二」在被送上烧烤架之前说了一句话，让全世界的蚝都涌向了陆地。
>
>『想要我的宝藏吗？如果想要的话，那就到地底下去找吧，我全部都放在那里。』
>
>世界开始迎接"牢ran时代"的来临。


RPC: http://challenge.xinshi.fun:8545/

faucet: http://challenge.xinshi.fun:8080/

请在下方**启动**你的靶机

## 部署注意事项

本题需要部分公共环境，或多容器部署

使用项目 [solidctf](https://github.com/chainflag/solidctf/)

## Writeup

> [!TIP]
> 建议前往 https://blog.shenghuo2.top/posts/bf0b486/ 获得最佳的阅读体验

---

- [生蚝的宝藏](#生蚝的宝藏)
  - [题目描述](#题目描述)
  - [部署注意事项](#部署注意事项)
  - [Writeup](#writeup)
    - [开始](#开始)
      - [bytecode](#bytecode)
    - [伪代码(使用dedaub)](#伪代码使用dedaub)
      - [反编译中缺失的东西](#反编译中缺失的东西)
      - [分析0x5cc4d812](#分析0x5cc4d812)
      - [重点](#重点)
      - [分析变量](#分析变量)
    - [伪代码(使用ethervm.io)](#伪代码使用ethervmio)
    - [TAC](#tac)
      - [分析0x5cc4d812](#分析0x5cc4d812-1)
      - [通过XOR反推](#通过xor反推)
    - [正式解题](#正式解题)
      - [varg0](#varg0)
    - [交互0x5cc4d812](#交互0x5cc4d812)
      - [CALLDATA](#calldata)
        - [静态类型](#静态类型)
        - [动态类型](#动态类型)
      - [辅助构造](#辅助构造)
    - [其他](#其他)
      - [合约源码](#合约源码)



> 总参赛队伍**1063** / 本题尝试队伍数**156** / 本题容器开启次数 **344** 
> **解出本题队伍18** / 提交wp队伍**15**
> 
> 基础知识可以看：[https://ctf-wiki.org/blockchain/ethereum/basics/](https://ctf-wiki.org/blockchain/ethereum/basics/)
> 
> 这位的Guide也很好：[https://cauliweak9.github.io/2024/04/28/Blockchain-Guide/](https://cauliweak9.github.io/2024/04/28/Blockchain-Guide/)


### 开始

题目没给源码，那就部署后，连上rpc读一下bytecode

```python
from web3 import Web3

RPC_URL = "http://106.15.138.99:8545/"
CONTRACT_ADDRESS = "0x20476fa3B6459a2Df5eF7B7f8dCA4620674282c8"

w3 = Web3(Web3.HTTPProvider(RPC_URL))

print(w3.eth.getCode(CONTRACT_ADDRESS).hex())
```

本人更喜欢直接通过geth attach连

我猜这一步阻止了大部分没接触过区块链的人，不知道给AI什么

curl 亦可

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  --data '{
    "jsonrpc": "2.0",
    "method": "eth_getCode",
    "params": ["0xff4D50B3dc7280DC32dA4174829c80cA661a905D", "latest"],
    "id": 1
  }' \
  http://challenge.xinshi.fun:8545/
```



#### bytecode

```
0x608060405234801561001057600080fd5b50600436106100365760003560e01c80635cc4d8121461003b57806364d98f6e14610050575b600080fd5b61004e61004936600461023a565b61006a565b005b60015460ff16604051901515815260200160405180910390f35b61007381610112565b60405160200161008391906102eb565b6040516020818303038152906040528051906020012060006040516020016100ab9190610326565b60405160208183030381529060405280519060200120146101035760405162461bcd60e51b815260206004820152600e60248201526d57726f6e6720547265617375726560901b604482015260640160405180910390fd5b506001805460ff191681179055565b60408051808201909152600c81526b35b2bcaf9b9b9b1c19981ab360a11b60208201528151606091839160009067ffffffffffffffff81111561015757610157610224565b6040519080825280601f01601f191660200182016040528015610181576020820181803683370190505b50905060005b835181101561021b578283518261019e91906103c2565b815181106101ae576101ae6103e4565b602001015160f81c60f81b60f81c8482815181106101ce576101ce6103e4565b602001015160f81c60f81b60f81c1860f81b8282815181106101f2576101f26103e4565b60200101906001600160f81b031916908160001a90535080610213816103fa565b915050610187565b50949350505050565b634e487b7160e01b600052604160045260246000fd5b60006020828403121561024c57600080fd5b813567ffffffffffffffff8082111561026457600080fd5b818401915084601f83011261027857600080fd5b81358181111561028a5761028a610224565b604051601f8201601f19908116603f011681019083821181831017156102b2576102b2610224565b816040528281528760208487010111156102cb57600080fd5b826020860160208301376000928101602001929092525095945050505050565b6000825160005b8181101561030c57602081860181015185830152016102f2565b8181111561031b576000828501525b509190910192915050565b600080835481600182811c91508083168061034257607f831692505b602080841082141561036257634e487b7160e01b86526022600452602486fd5b8180156103765760018114610387576103b4565b60ff198616895284890196506103b4565b60008a81526020902060005b868110156103ac5781548b820152908501908301610393565b505084890196505b509498975050505050505050565b6000826103df57634e487b7160e01b600052601260045260246000fd5b500690565b634e487b7160e01b600052603260045260246000fd5b600060001982141561041c57634e487b7160e01b600052601160045260246000fd5b506001019056fea2646970667358221220151b46d09b4bba2396ad66d34580f5cdde40717a0a129d5e46218ae19a81e83164736f6c63430008090033
```

然后扔去decompile

### 伪代码(使用dedaub)

https://app.dedaub.com/decompile

单看decompile的内容其实不够完整，丢了一些东西(不确定是哪里的问题)

```solidity
// Decompiled by library.dedaub.com
// 2025.08.13 16:34 UTC
// Compiled using the solidity compiler version 0.8.9


// Data structures and variables inferred from the use of storage instructions
uint256[] array_0; // STORAGE[0x0]
bool _isSolved; // STORAGE[0x1] bytes 0 to 0



function fallback() public payable { 
    revert();
}

function 0x5cc4d812(bytes varg0) public payable { 
    require(msg.data.length - 4 >= 32);
    require(varg0 <= uint64.max);
    require(4 + varg0 + 31 < msg.data.length);
    require(varg0.length <= uint64.max, Panic(65)); // failed memory allocation (too much memory)
    v0 = new bytes[](varg0.length);
    require(!((v0 + (63 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & varg0.length + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) < v0) | (v0 + (63 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & varg0.length + 31) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) > uint64.max)), Panic(65)); // failed memory allocation (too much memory)
    require(4 + varg0 + varg0.length + 32 <= msg.data.length);
    CALLDATACOPY(v0.data, varg0.data, varg0.length);
    v0[varg0.length] = 0;
    require(v0.length <= uint64.max, Panic(65)); // failed memory allocation (too much memory)
    v1 = new bytes[](v0.length);
    if (v0.length) {
        CALLDATACOPY(v1.data, msg.data.length, v0.length);
    }
    v2 = v3 = 0;
    while (v2 < v0.length) {
        require(v4.length, Panic(18)); // division by zero
        require(v2 % v4.length < v4.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
        require(v2 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
        require(v2 < v1.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
        MEM8[32 + v2 + v1] = (byte(bytes1((v0[v2] >> 248 << 248 >> 248 ^ v4[v2 % v4.length] >> 248 << 248 >> 248) << 248), 0x0)) & 0xFF;
        require(v2 != uint256.max, Panic(17)); // arithmetic overflow or underflow
        v2 += 1;
    }
    v5 = new uint256[](v1.length + v5.data - MEM[64] - 32);
    v6 = v7 = 0;
    while (v6 < v1.length) {
        MEM[v6 + v5.data] = v1[v6];
        v6 += 32;
    }
    if (v6 > v1.length) {
        MEM[v5.data + v1.length] = 0;
    }
    MEM[64] = v1.length + v5.data;
    v8 = v5.length;
    v9 = v5.data;
    v10 = new uint256[](v11 - MEM[64] - 32);
    v11 = v12 = 0;
    v13 = v14 = array_0.length >> 1;
    if (!(array_0.length & 0x1)) {
        v13 = v15 = v14 & 0x7f;
    }
    require(array_0.length & 0x1 != v13 < 32, Panic(34)); // access to incorrectly encoded storage byte array
    if (!(array_0.length & 0x1)) {
        MEM[v10.data] = bytes31(array_0.length);
        v11 = v16 = v10.data + v13;
    } else if (array_0.length & 0x1 == 1) {
        v17 = v18 = array_0.data;
        v19 = v20 = 0;
        while (v19 < v13) {
            MEM[v19 + v10.data] = STORAGE[v17];
            v17 += 1;
            v19 += 32;
        }
        v11 = v21 = v10.data + v13;
    }
    v22 = v10.length;
    v23 = v10.data;
    require(keccak256(v10) == keccak256(v5), Error('Wrong Treasure'));
    _isSolved = 1;
}

function isSolved() public payable { 
    return _isSolved;
}

// Note: The function selector is not present in the original solidity code.
// However, we display it for the sake of completeness.

function __function_selector__( function_selector) public payable { 
    MEM[64] = 128;
    require(!msg.value);
    if (msg.data.length >= 4) {
        if (0x5cc4d812 == function_selector >> 224) {
            0x5cc4d812();
        } else if (0x64d98f6e == function_selector >> 224) {
            isSolved();
        }
    }
    fallback();
}
```

#### 反编译中缺失的东西


```
MEM8[32 + v2 + v1] = (byte(bytes1((v0[v2] >> 248 << 248 >> 248 ^ v4[v2 % v4.length] >> 248 << 248 >> 248) << 248), 0x0)) & 0xFF;
```

进行了一个xor操作，但xor用的值`v4`，不知道是什么

在这个伪代码中没有被明确定义，或者说丢失

同样的，用 https://ethervm.io/decompile 来反编译也是缺失的



#### 分析0x5cc4d812

先来解释一下这个函数名是啥

> 以太坊虚拟机中的函数调用由交易发送数据的前四个字节指定。这些 4 字节签名定义为函数签名规范表示的 Keccak 哈希值 (SHA3) 的前四个字节。

所以，`fallback()`，`isSolved()`，`__function_selector__( function_selector)` 其实都是0xaabbccdd这种格式的，只不过太过常见，被记录了，就像是cmd5查询一样

来看`0x5cc4d812`的参数，**varg0**

用CALLDATACOPY把varg0克隆为v0

```solidity
CALLDATACOPY(v0.data, varg0.data, varg0.length);
```

v0和这个不知道的v4进行按位异或，存为v5

```
v0[v2] ^ v4[v2 % v4.length]
```

v10是slot0，也就是array_0

然后v10和v5比较，如果相同，就把_isSolved设为True

```solidity
    require(keccak256(v10) == keccak256(v5), Error('Wrong Treasure'));
    _isSolved = 1;
```

#### 重点

也就是说本题只需要，找到v4和array_0的值，发给0x5cc4d812即可

*当然，不愿意手工分析的话，可以扔给ai让他还原到接近源码*

#### 分析变量

这个伪代码中设计的变量作用分别是：

- **varg0**: 函数输入参数，是一个字节数组（用户提供的输入）
- **v0**: 从varg0复制的字节数组，是用户输入的副本
- **v1**: 一个新的字节数组，用于存储对v0处理后的结果
  - 这是经过某种变换（可能是解密）后的数据
- **v2**: 循环计数器，用于遍历v0的每个字节
- **v4**: 未明确定义的数组，似乎是用作密钥
- - 用于与v0的字节进行XOR操作
  - 每个字节使用`v0[v2] ^ v4[v2 % v4.length]`进行变换
- **v5**: 从v1转换而来的数组
  - 实际上是将v1的内容重新打包成一个新的数据结构
- **v8, v9**: v5的长度和数据指针
- **v10**: 从合约storage slot 0(array_0)中读取的数据
- **v11, v12, v13, v14**: 用于处理array_0数据的临时变量和偏移量
- **v22, v23**: v10的长度和数据指针

### 伪代码(使用ethervm.io)

https://ethervm.io/decompile

这里不太展开讲，只是作为补充

只是看到有很多选手的wp说这个的结果有问题，没有key，为ta正名一下（

```
memory[temp0 + 0x20:temp0 + 0x20 + 0x20] = 0x35b2bcaf9b9b9b1c19981ab3 << 0xa1;
```

AI可能会忽略掉这个数值

```
>>> hex(0x35b2bcaf9a9b9a1c19199ab3<<0xa1)
'0x6b65795f35373438323335660000000000000000000000000000000000000000'
```

但这就是`key`的值

也对应了下面TAC里的

```assembly
0x130S0x6a: v130V6a(0x6b65795f37373638333035660000000000000000000000000000000000000000) = SHL v12eV6a(0xa1), v121V6a(0x35b2bcaf9b9b9b1c19981ab3) //SHL是左移
```

（这里展示的是左移后的结果，所以会比较好找）

### TAC

可以再找到TAC（Three Address Code，三地址码），加入分析

可见于 https://app.dedaub.com/decompile?md5=3e5cd84a9f17d30b0c23b7133f5c99e8

<details>
<summary>约900行代码</summary>


```assembly
function __function_selector__() public {
    Begin block 0x0
    prev=[], succ=[0xc, 0x10]
    =================================
    0x0: v0(0x80) = CONST 
    0x2: v2(0x40) = CONST 
    0x4: MSTORE v2(0x40), v0(0x80)
    0x5: v5 = CALLVALUE 
    0x7: v7 = ISZERO v5
    0x8: v8(0x10) = CONST 
    0xb: JUMPI v8(0x10), v7

    Begin block 0xc
    prev=[0x0], succ=[]
    =================================
    0xc: vc(0x0) = CONST 
    0xf: REVERT vc(0x0), vc(0x0)

    Begin block 0x10
    prev=[0x0], succ=[0x1a, 0x143d]
    =================================
    0x12: v12(0x4) = CONST 
    0x14: v14 = CALLDATASIZE 
    0x15: v15 = LT v14, v12(0x4)
    0x1437: v1437(0x143d) = CONST 
    0x1438: JUMPI v1437(0x143d), v15

    Begin block 0x1a
    prev=[0x10], succ=[0x1440, 0x2b]
    =================================
    0x1a: v1a(0x0) = CONST 
    0x1c: v1c = CALLDATALOAD v1a(0x0)
    0x1d: v1d(0xe0) = CONST 
    0x1f: v1f = SHR v1d(0xe0), v1c
    0x21: v21(0x5cc4d812) = CONST 
    0x26: v26 = EQ v21(0x5cc4d812), v1f
    0x1439: v1439(0x1440) = CONST 
    0x143a: JUMPI v1439(0x1440), v26

    Begin block 0x1440
    prev=[0x1a], succ=[]
    =================================
    0x1441: v1441(0x3b) = CONST 
    0x1442: CALLPRIVATE v1441(0x3b)

    Begin block 0x2b
    prev=[0x1a], succ=[0x143d, 0x1443]
    =================================
    0x2c: v2c(0x64d98f6e) = CONST 
    0x31: v31 = EQ v2c(0x64d98f6e), v1f
    0x143b: v143b(0x1443) = CONST 
    0x143c: JUMPI v143b(0x1443), v31

    Begin block 0x143d
    prev=[0x10, 0x2b], succ=[]
    =================================
    0x143e: v143e(0x36) = CONST 
    0x143f: CALLPRIVATE v143e(0x36)

    Begin block 0x1443
    prev=[0x2b], succ=[]
    =================================
    0x1444: v1444(0x50) = CONST 
    0x1445: CALLPRIVATE v1444(0x50)

}

function fallback()() public {
    Begin block 0x36
    prev=[], succ=[]
    =================================
    0x37: v37(0x0) = CONST 
    0x3a: REVERT v37(0x0), v37(0x0)

}

function 0x5cc4d812() public {
    Begin block 0x3b
    prev=[], succ=[0x23a]
    =================================
    0x3c: v3c(0x4e) = CONST 
    0x3f: v3f(0x49) = CONST 
    0x42: v42 = CALLDATASIZE 
    0x43: v43(0x4) = CONST 
    0x45: v45(0x23a) = CONST 
    0x48: JUMP v45(0x23a)

    Begin block 0x23a
    prev=[0x3b], succ=[0x248, 0x24c]
    =================================
    0x23b: v23b(0x0) = CONST 
    0x23d: v23d(0x20) = CONST 
    0x241: v241 = SUB v42, v43(0x4)
    0x242: v242 = SLT v241, v23d(0x20)
    0x243: v243 = ISZERO v242
    0x244: v244(0x24c) = CONST 
    0x247: JUMPI v244(0x24c), v243

    Begin block 0x248
    prev=[0x23a], succ=[]
    =================================
    0x248: v248(0x0) = CONST 
    0x24b: REVERT v248(0x0), v248(0x0)

    Begin block 0x24c
    prev=[0x23a], succ=[0x260, 0x264]
    =================================
    0x24e: v24e = CALLDATALOAD v43(0x4)
    0x24f: v24f(0xffffffffffffffff) = CONST 
    0x25a: v25a = GT v24e, v24f(0xffffffffffffffff)
    0x25b: v25b = ISZERO v25a
    0x25c: v25c(0x264) = CONST 
    0x25f: JUMPI v25c(0x264), v25b

    Begin block 0x260
    prev=[0x24c], succ=[]
    =================================
    0x260: v260(0x0) = CONST 
    0x263: REVERT v260(0x0), v260(0x0)

    Begin block 0x264
    prev=[0x24c], succ=[0x274, 0x278]
    =================================
    0x267: v267 = ADD v43(0x4), v24e
    0x26b: v26b(0x1f) = CONST 
    0x26e: v26e = ADD v267, v26b(0x1f)
    0x26f: v26f = SLT v26e, v42
    0x270: v270(0x278) = CONST 
    0x273: JUMPI v270(0x278), v26f

    Begin block 0x274
    prev=[0x264], succ=[]
    =================================
    0x274: v274(0x0) = CONST 
    0x277: REVERT v274(0x0), v274(0x0)

    Begin block 0x278
    prev=[0x264], succ=[0x283, 0x28a]
    =================================
    0x27a: v27a = CALLDATALOAD v267
    0x27d: v27d = GT v27a, v24f(0xffffffffffffffff)
    0x27e: v27e = ISZERO v27d
    0x27f: v27f(0x28a) = CONST 
    0x282: JUMPI v27f(0x28a), v27e

    Begin block 0x283
    prev=[0x278], succ=[0x9a4]
    =================================
    0x283: v283(0x28a) = CONST 
    0x286: v286(0x9a4) = CONST 
    0x289: JUMP v286(0x9a4)

    Begin block 0x9a4
    prev=[0x283], succ=[]
    =================================
    0x9a5: v9a5(0x4e487b71) = CONST 
    0x9aa: v9aa(0xe0) = CONST 
    0x9ac: v9ac(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v9aa(0xe0), v9a5(0x4e487b71)
    0x9ad: v9ad(0x0) = CONST 
    0x9af: MSTORE v9ad(0x0), v9ac(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x9b0: v9b0(0x41) = CONST 
    0x9b2: v9b2(0x4) = CONST 
    0x9b4: MSTORE v9b2(0x4), v9b0(0x41)
    0x9b5: v9b5(0x24) = CONST 
    0x9b7: v9b7(0x0) = CONST 
    0x9b9: REVERT v9b7(0x0), v9b5(0x24)

    Begin block 0x28a
    prev=[0x278], succ=[0x2ab, 0x2b2]
    =================================
    0x28b: v28b(0x40) = CONST 
    0x28d: v28d = MLOAD v28b(0x40)
    0x28e: v28e(0x1f) = CONST 
    0x291: v291 = ADD v27a, v28e(0x1f)
    0x292: v292(0x1f) = CONST 
    0x294: v294(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) = NOT v292(0x1f)
    0x297: v297 = AND v294(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0), v291
    0x298: v298(0x3f) = CONST 
    0x29a: v29a = ADD v298(0x3f), v297
    0x29b: v29b = AND v29a, v294(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0)
    0x29d: v29d = ADD v28d, v29b
    0x2a1: v2a1 = GT v29d, v24f(0xffffffffffffffff)
    0x2a4: v2a4 = LT v29d, v28d
    0x2a5: v2a5 = OR v2a4, v2a1
    0x2a6: v2a6 = ISZERO v2a5
    0x2a7: v2a7(0x2b2) = CONST 
    0x2aa: JUMPI v2a7(0x2b2), v2a6

    Begin block 0x2ab
    prev=[0x28a], succ=[0x9d9]
    =================================
    0x2ab: v2ab(0x2b2) = CONST 
    0x2ae: v2ae(0x9d9) = CONST 
    0x2b1: JUMP v2ae(0x9d9)

    Begin block 0x9d9
    prev=[0x2ab], succ=[]
    =================================
    0x9da: v9da(0x4e487b71) = CONST 
    0x9df: v9df(0xe0) = CONST 
    0x9e1: v9e1(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v9df(0xe0), v9da(0x4e487b71)
    0x9e2: v9e2(0x0) = CONST 
    0x9e4: MSTORE v9e2(0x0), v9e1(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x9e5: v9e5(0x41) = CONST 
    0x9e7: v9e7(0x4) = CONST 
    0x9e9: MSTORE v9e7(0x4), v9e5(0x41)
    0x9ea: v9ea(0x24) = CONST 
    0x9ec: v9ec(0x0) = CONST 
    0x9ee: REVERT v9ec(0x0), v9ea(0x24)

    Begin block 0x2b2
    prev=[0x28a], succ=[0x2c7, 0x2cb]
    =================================
    0x2b4: v2b4(0x40) = CONST 
    0x2b6: MSTORE v2b4(0x40), v29d
    0x2b9: MSTORE v28d, v27a
    0x2bb: v2bb(0x20) = CONST 
    0x2bf: v2bf = ADD v267, v27a
    0x2c0: v2c0 = ADD v2bf, v2bb(0x20)
    0x2c1: v2c1 = GT v2c0, v42
    0x2c2: v2c2 = ISZERO v2c1
    0x2c3: v2c3(0x2cb) = CONST 
    0x2c6: JUMPI v2c3(0x2cb), v2c2

    Begin block 0x2c7
    prev=[0x2b2], succ=[]
    =================================
    0x2c7: v2c7(0x0) = CONST 
    0x2ca: REVERT v2c7(0x0), v2c7(0x0)

    Begin block 0x2cb
    prev=[0x2b2], succ=[0x49]
    =================================
    0x2cd: v2cd(0x20) = CONST 
    0x2d0: v2d0 = ADD v267, v2cd(0x20)
    0x2d1: v2d1(0x20) = CONST 
    0x2d4: v2d4 = ADD v28d, v2d1(0x20)
    0x2d5: CALLDATACOPY v2d4, v2d0, v27a
    0x2d6: v2d6(0x0) = CONST 
    0x2da: v2da = ADD v28d, v27a
    0x2db: v2db(0x20) = CONST 
    0x2dd: v2dd = ADD v2db(0x20), v2da
    0x2e1: MSTORE v2dd, v2d6(0x0)
    0x2ea: JUMP v3f(0x49)

    Begin block 0x49
    prev=[0x2cb], succ=[0x6a]
    =================================
    0x4a: v4a(0x6a) = CONST 
    0x4d: JUMP v4a(0x6a)

    Begin block 0x6a
    prev=[0x49], succ=[0x112B0x6a]
    =================================
    0x6b: v6b(0x73) = CONST 
    0x6f: v6f(0x112) = CONST 
    0x72: JUMP v6f(0x112)

    Begin block 0x112B0x6a
    prev=[0x6a], succ=[0x150B0x6a, 0x157B0x6a]
    =================================
    0x113S0x6a: v113V6a(0x40) = CONST 
    0x116S0x6a: v116V6a = MLOAD v113V6a(0x40)
    0x119S0x6a: v119V6a = ADD v113V6a(0x40), v116V6a
    0x11cS0x6a: MSTORE v113V6a(0x40), v119V6a
    0x11dS0x6a: v11dV6a(0xc) = CONST 
    0x120S0x6a: MSTORE v116V6a, v11dV6a(0xc)
    0x121S0x6a: v121V6a(0x35b2bcaf9b9b9b1c19981ab3) = CONST 
    0x12eS0x6a: v12eV6a(0xa1) = CONST 
    0x130S0x6a: v130V6a(0x6b65795f37373638333035660000000000000000000000000000000000000000) = SHL v12eV6a(0xa1), v121V6a(0x35b2bcaf9b9b9b1c19981ab3)
    0x131S0x6a: v131V6a(0x20) = CONST 
    0x134S0x6a: v134V6a = ADD v116V6a, v131V6a(0x20)
    0x135S0x6a: MSTORE v134V6a, v130V6a(0x6b65795f37373638333035660000000000000000000000000000000000000000)
    0x137S0x6a: v137V6a = MLOAD v28d
    0x138S0x6a: v138V6a(0x60) = CONST 
    0x13dS0x6a: v13dV6a(0x0) = CONST 
    0x140S0x6a: v140V6a(0xffffffffffffffff) = CONST 
    0x14aS0x6a: v14aV6a = GT v137V6a, v140V6a(0xffffffffffffffff)
    0x14bS0x6a: v14bV6a = ISZERO v14aV6a
    0x14cS0x6a: v14cV6a(0x157) = CONST 
    0x14fS0x6a: JUMPI v14cV6a(0x157), v14bV6a

    Begin block 0x150B0x6a
    prev=[0x112B0x6a], succ=[0x8d0B0x6a]
    =================================
    0x150S0x6a: v150V6a(0x157) = CONST 
    0x153S0x6a: v153V6a(0x8d0) = CONST 
    0x156S0x6a: JUMP v153V6a(0x8d0)

    Begin block 0x8d0B0x6a
    prev=[0x150B0x6a], succ=[]
    =================================
    0x8d1S0x6a: v8d1V6a(0x4e487b71) = CONST 
    0x8d6S0x6a: v8d6V6a(0xe0) = CONST 
    0x8d8S0x6a: v8d8V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v8d6V6a(0xe0), v8d1V6a(0x4e487b71)
    0x8d9S0x6a: v8d9V6a(0x0) = CONST 
    0x8dbS0x6a: MSTORE v8d9V6a(0x0), v8d8V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x8dcS0x6a: v8dcV6a(0x41) = CONST 
    0x8deS0x6a: v8deV6a(0x4) = CONST 
    0x8e0S0x6a: MSTORE v8deV6a(0x4), v8dcV6a(0x41)
    0x8e1S0x6a: v8e1V6a(0x24) = CONST 
    0x8e3S0x6a: v8e3V6a(0x0) = CONST 
    0x8e5S0x6a: REVERT v8e3V6a(0x0), v8e1V6a(0x24)

    Begin block 0x157B0x6a
    prev=[0x112B0x6a], succ=[0x175B0x6a, 0x181B0x6a]
    =================================
    0x158S0x6a: v158V6a(0x40) = CONST 
    0x15aS0x6a: v15aV6a = MLOAD v158V6a(0x40)
    0x15eS0x6a: MSTORE v15aV6a, v137V6a
    0x160S0x6a: v160V6a(0x1f) = CONST 
    0x162S0x6a: v162V6a = ADD v160V6a(0x1f), v137V6a
    0x163S0x6a: v163V6a(0x1f) = CONST 
    0x165S0x6a: v165V6a(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) = NOT v163V6a(0x1f)
    0x166S0x6a: v166V6a = AND v165V6a(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0), v162V6a
    0x167S0x6a: v167V6a(0x20) = CONST 
    0x169S0x6a: v169V6a = ADD v167V6a(0x20), v166V6a
    0x16bS0x6a: v16bV6a = ADD v15aV6a, v169V6a
    0x16cS0x6a: v16cV6a(0x40) = CONST 
    0x16eS0x6a: MSTORE v16cV6a(0x40), v16bV6a
    0x170S0x6a: v170V6a = ISZERO v137V6a
    0x171S0x6a: v171V6a(0x181) = CONST 
    0x174S0x6a: JUMPI v171V6a(0x181), v170V6a

    Begin block 0x175B0x6a
    prev=[0x157B0x6a], succ=[0x181B0x6a]
    =================================
    0x175S0x6a: v175V6a(0x20) = CONST 
    0x178S0x6a: v178V6a = ADD v15aV6a, v175V6a(0x20)
    0x17bS0x6a: v17bV6a = CALLDATASIZE 
    0x17dS0x6a: CALLDATACOPY v178V6a, v17bV6a, v137V6a
    0x17eS0x6a: v17eV6a = ADD v137V6a, v178V6a

    Begin block 0x181B0x6a
    prev=[0x175B0x6a, 0x157B0x6a], succ=[0x187B0x6a]
    =================================
    0x185S0x6a: v185V6a(0x0) = CONST 

    Begin block 0x187B0x6a
    prev=[0x181B0x6a, 0x213B0x6a], succ=[0x191B0x6a, 0x21bB0x6a]
    =================================
    0x187_0x0S0x6a: v187_0V6a = PHI v185V6a(0x0), v420V6a
    0x189S0x6a: v189V6a = MLOAD v28d
    0x18bS0x6a: v18bV6a = LT v187_0V6a, v189V6a
    0x18cS0x6a: v18cV6a = ISZERO v18bV6a
    0x18dS0x6a: v18dV6a(0x21b) = CONST 
    0x190S0x6a: JUMPI v18dV6a(0x21b), v18cV6a

    Begin block 0x191B0x6a
    prev=[0x187B0x6a], succ=[0x3c2B0x6a]
    =================================
    0x193S0x6a: v193V6a(0xc) = MLOAD v116V6a
    0x195S0x6a: v195V6a(0x19e) = CONST 
    0x19aS0x6a: v19aV6a(0x3c2) = CONST 
    0x19dS0x6a: JUMP v19aV6a(0x3c2)

    Begin block 0x3c2B0x6a
    prev=[0x191B0x6a], succ=[0x3caB0x6a, 0x3dfB0x6a]
    =================================
    0x3c3S0x6a: v3c3V6a(0x0) = CONST 
    0x3c6S0x6a: v3c6V6a(0x3df) = CONST 
    0x3c9S0x6a: JUMPI v3c6V6a(0x3df), v193V6a(0xc)

    Begin block 0x3caB0x6a
    prev=[0x3c2B0x6a], succ=[]
    =================================
    0x3caS0x6a: v3caV6a(0x4e487b71) = CONST 
    0x3cfS0x6a: v3cfV6a(0xe0) = CONST 
    0x3d1S0x6a: v3d1V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v3cfV6a(0xe0), v3caV6a(0x4e487b71)
    0x3d2S0x6a: v3d2V6a(0x0) = CONST 
    0x3d4S0x6a: MSTORE v3d2V6a(0x0), v3d1V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x3d5S0x6a: v3d5V6a(0x12) = CONST 
    0x3d7S0x6a: v3d7V6a(0x4) = CONST 
    0x3d9S0x6a: MSTORE v3d7V6a(0x4), v3d5V6a(0x12)
    0x3daS0x6a: v3daV6a(0x24) = CONST 
    0x3dcS0x6a: v3dcV6a(0x0) = CONST 
    0x3deS0x6a: REVERT v3dcV6a(0x0), v3daV6a(0x24)

    Begin block 0x3dfB0x6a
    prev=[0x3c2B0x6a], succ=[0x19eB0x6a]
    =================================
    0x3df_0x1S0x6a: v3df_1V6a = PHI v185V6a(0x0), v420V6a
    0x3e1S0x6a: v3e1V6a = MOD v3df_1V6a, v193V6a(0xc)
    0x3e3S0x6a: JUMP v195V6a(0x19e)

    Begin block 0x19eB0x6a
    prev=[0x3dfB0x6a], succ=[0x1a7B0x6a, 0x1aeB0x6a]
    =================================
    0x1a0S0x6a: v1a0V6a(0xc) = MLOAD v116V6a
    0x1a2S0x6a: v1a2V6a = LT v3e1V6a, v1a0V6a(0xc)
    0x1a3S0x6a: v1a3V6a(0x1ae) = CONST 
    0x1a6S0x6a: JUMPI v1a3V6a(0x1ae), v1a2V6a

    Begin block 0x1a7B0x6a
    prev=[0x19eB0x6a], succ=[0x905B0x6a]
    =================================
    0x1a7S0x6a: v1a7V6a(0x1ae) = CONST 
    0x1aaS0x6a: v1aaV6a(0x905) = CONST 
    0x1adS0x6a: JUMP v1aaV6a(0x905)

    Begin block 0x905B0x6a
    prev=[0x1a7B0x6a], succ=[]
    =================================
    0x906S0x6a: v906V6a(0x4e487b71) = CONST 
    0x90bS0x6a: v90bV6a(0xe0) = CONST 
    0x90dS0x6a: v90dV6a(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v90bV6a(0xe0), v906V6a(0x4e487b71)
    0x90eS0x6a: v90eV6a(0x0) = CONST 
    0x910S0x6a: MSTORE v90eV6a(0x0), v90dV6a(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x911S0x6a: v911V6a(0x32) = CONST 
    0x913S0x6a: v913V6a(0x4) = CONST 
    0x915S0x6a: MSTORE v913V6a(0x4), v911V6a(0x32)
    0x916S0x6a: v916V6a(0x24) = CONST 
    0x918S0x6a: v918V6a(0x0) = CONST 
    0x91aS0x6a: REVERT v918V6a(0x0), v916V6a(0x24)

    Begin block 0x1aeB0x6a
    prev=[0x19eB0x6a], succ=[0x1c7B0x6a, 0x1ceB0x6a]
    =================================
    0x1ae_0x2S0x6a: v1ae_2V6a = PHI v185V6a(0x0), v420V6a
    0x1afS0x6a: v1afV6a(0x20) = CONST 
    0x1b1S0x6a: v1b1V6a = ADD v1afV6a(0x20), v3e1V6a
    0x1b2S0x6a: v1b2V6a = ADD v1b1V6a, v116V6a
    0x1b3S0x6a: v1b3V6a = MLOAD v1b2V6a
    0x1b4S0x6a: v1b4V6a(0xf8) = CONST 
    0x1b6S0x6a: v1b6V6a = SHR v1b4V6a(0xf8), v1b3V6a
    0x1b7S0x6a: v1b7V6a(0xf8) = CONST 
    0x1b9S0x6a: v1b9V6a = SHL v1b7V6a(0xf8), v1b6V6a
    0x1baS0x6a: v1baV6a(0xf8) = CONST 
    0x1bcS0x6a: v1bcV6a = SHR v1baV6a(0xf8), v1b9V6a
    0x1c0S0x6a: v1c0V6a = MLOAD v28d
    0x1c2S0x6a: v1c2V6a = LT v1ae_2V6a, v1c0V6a
    0x1c3S0x6a: v1c3V6a(0x1ce) = CONST 
    0x1c6S0x6a: JUMPI v1c3V6a(0x1ce), v1c2V6a

    Begin block 0x1c7B0x6a
    prev=[0x1aeB0x6a], succ=[0x93aB0x6a]
    =================================
    0x1c7S0x6a: v1c7V6a(0x1ce) = CONST 
    0x1caS0x6a: v1caV6a(0x93a) = CONST 
    0x1cdS0x6a: JUMP v1caV6a(0x93a)

    Begin block 0x93aB0x6a
    prev=[0x1c7B0x6a], succ=[]
    =================================
    0x93bS0x6a: v93bV6a(0x4e487b71) = CONST 
    0x940S0x6a: v940V6a(0xe0) = CONST 
    0x942S0x6a: v942V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v940V6a(0xe0), v93bV6a(0x4e487b71)
    0x943S0x6a: v943V6a(0x0) = CONST 
    0x945S0x6a: MSTORE v943V6a(0x0), v942V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x946S0x6a: v946V6a(0x32) = CONST 
    0x948S0x6a: v948V6a(0x4) = CONST 
    0x94aS0x6a: MSTORE v948V6a(0x4), v946V6a(0x32)
    0x94bS0x6a: v94bV6a(0x24) = CONST 
    0x94dS0x6a: v94dV6a(0x0) = CONST 
    0x94fS0x6a: REVERT v94dV6a(0x0), v94bV6a(0x24)

    Begin block 0x1ceB0x6a
    prev=[0x1aeB0x6a], succ=[0x1ebB0x6a, 0x1f2B0x6a]
    =================================
    0x1ce_0x0S0x6a: v1ce_0V6a = PHI v185V6a(0x0), v420V6a
    0x1ce_0x3S0x6a: v1ce_3V6a = PHI v185V6a(0x0), v420V6a
    0x1cfS0x6a: v1cfV6a(0x20) = CONST 
    0x1d1S0x6a: v1d1V6a = ADD v1cfV6a(0x20), v1ce_0V6a
    0x1d2S0x6a: v1d2V6a = ADD v1d1V6a, v28d
    0x1d3S0x6a: v1d3V6a = MLOAD v1d2V6a
    0x1d4S0x6a: v1d4V6a(0xf8) = CONST 
    0x1d6S0x6a: v1d6V6a = SHR v1d4V6a(0xf8), v1d3V6a
    0x1d7S0x6a: v1d7V6a(0xf8) = CONST 
    0x1d9S0x6a: v1d9V6a = SHL v1d7V6a(0xf8), v1d6V6a
    0x1daS0x6a: v1daV6a(0xf8) = CONST 
    0x1dcS0x6a: v1dcV6a = SHR v1daV6a(0xf8), v1d9V6a
    0x1ddS0x6a: v1ddV6a = XOR v1dcV6a, v1bcV6a
    0x1deS0x6a: v1deV6a(0xf8) = CONST 
    0x1e0S0x6a: v1e0V6a = SHL v1deV6a(0xf8), v1ddV6a
    0x1e4S0x6a: v1e4V6a = MLOAD v15aV6a
    0x1e6S0x6a: v1e6V6a = LT v1ce_3V6a, v1e4V6a
    0x1e7S0x6a: v1e7V6a(0x1f2) = CONST 
    0x1eaS0x6a: JUMPI v1e7V6a(0x1f2), v1e6V6a

    Begin block 0x1ebB0x6a
    prev=[0x1ceB0x6a], succ=[0x96fB0x6a]
    =================================
    0x1ebS0x6a: v1ebV6a(0x1f2) = CONST 
    0x1eeS0x6a: v1eeV6a(0x96f) = CONST 
    0x1f1S0x6a: JUMP v1eeV6a(0x96f)

    Begin block 0x96fB0x6a
    prev=[0x1ebB0x6a], succ=[]
    =================================
    0x970S0x6a: v970V6a(0x4e487b71) = CONST 
    0x975S0x6a: v975V6a(0xe0) = CONST 
    0x977S0x6a: v977V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v975V6a(0xe0), v970V6a(0x4e487b71)
    0x978S0x6a: v978V6a(0x0) = CONST 
    0x97aS0x6a: MSTORE v978V6a(0x0), v977V6a(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x97bS0x6a: v97bV6a(0x32) = CONST 
    0x97dS0x6a: v97dV6a(0x4) = CONST 
    0x97fS0x6a: MSTORE v97dV6a(0x4), v97bV6a(0x32)
    0x980S0x6a: v980V6a(0x24) = CONST 
    0x982S0x6a: v982V6a(0x0) = CONST 
    0x984S0x6a: REVERT v982V6a(0x0), v980V6a(0x24)

    Begin block 0x1f2B0x6a
    prev=[0x1ceB0x6a], succ=[0x3faB0x6a]
    =================================
    0x1f2_0x0S0x6a: v1f2_0V6a = PHI v185V6a(0x0), v420V6a
    0x1f3S0x6a: v1f3V6a(0x20) = CONST 
    0x1f5S0x6a: v1f5V6a = ADD v1f3V6a(0x20), v1f2_0V6a
    0x1f6S0x6a: v1f6V6a = ADD v1f5V6a, v15aV6a
    0x1f8S0x6a: v1f8V6a(0x1) = CONST 
    0x1faS0x6a: v1faV6a(0x1) = CONST 
    0x1fcS0x6a: v1fcV6a(0xf8) = CONST 
    0x1feS0x6a: v1feV6a(0x100000000000000000000000000000000000000000000000000000000000000) = SHL v1fcV6a(0xf8), v1faV6a(0x1)
    0x1ffS0x6a: v1ffV6a(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) = SUB v1feV6a(0x100000000000000000000000000000000000000000000000000000000000000), v1f8V6a(0x1)
    0x200S0x6a: v200V6a(0xff00000000000000000000000000000000000000000000000000000000000000) = NOT v1ffV6a(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    0x201S0x6a: v201V6a = AND v200V6a(0xff00000000000000000000000000000000000000000000000000000000000000), v1e0V6a
    0x204S0x6a: v204V6a(0x0) = CONST 
    0x206S0x6a: v206V6a = BYTE v204V6a(0x0), v201V6a
    0x208S0x6a: MSTORE8 v1f6V6a, v206V6a
    0x20bS0x6a: v20bV6a(0x213) = CONST 
    0x20fS0x6a: v20fV6a(0x3fa) = CONST 
    0x212S0x6a: JUMP v20fV6a(0x3fa)

    Begin block 0x3faB0x6a
    prev=[0x1f2B0x6a], succ=[0x407B0x6a, 0x41cB0x6a]
    =================================
    0x3fa_0x0S0x6a: v3fa_0V6a = PHI v185V6a(0x0), v420V6a
    0x3fbS0x6a: v3fbV6a(0x0) = CONST 
    0x3fdS0x6a: v3fdV6a(0x0) = CONST 
    0x3ffS0x6a: v3ffV6a(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) = NOT v3fdV6a(0x0)
    0x401S0x6a: v401V6a = EQ v3fa_0V6a, v3ffV6a(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    0x402S0x6a: v402V6a = ISZERO v401V6a
    0x403S0x6a: v403V6a(0x41c) = CONST 
    0x406S0x6a: JUMPI v403V6a(0x41c), v402V6a

    Begin block 0x407B0x6a
    prev=[0x3faB0x6a], succ=[]
    =================================
    0x407S0x6a: v407V6a(0x4e487b71) = CONST 
    0x40cS0x6a: v40cV6a(0xe0) = CONST 
    0x40eS0x6a: v40eV6a(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v40cV6a(0xe0), v407V6a(0x4e487b71)
    0x40fS0x6a: v40fV6a(0x0) = CONST 
    0x411S0x6a: MSTORE v40fV6a(0x0), v40eV6a(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x412S0x6a: v412V6a(0x11) = CONST 
    0x414S0x6a: v414V6a(0x4) = CONST 
    0x416S0x6a: MSTORE v414V6a(0x4), v412V6a(0x11)
    0x417S0x6a: v417V6a(0x24) = CONST 
    0x419S0x6a: v419V6a(0x0) = CONST 
    0x41bS0x6a: REVERT v419V6a(0x0), v417V6a(0x24)

    Begin block 0x41cB0x6a
    prev=[0x3faB0x6a], succ=[0x213B0x6a]
    =================================
    0x41c_0x1S0x6a: v41c_1V6a = PHI v185V6a(0x0), v420V6a
    0x41eS0x6a: v41eV6a(0x1) = CONST 
    0x420S0x6a: v420V6a = ADD v41eV6a(0x1), v41c_1V6a
    0x422S0x6a: JUMP v20bV6a(0x213)

    Begin block 0x213B0x6a
    prev=[0x41cB0x6a], succ=[0x187B0x6a]
    =================================
    0x217S0x6a: v217V6a(0x187) = CONST 
    0x21aS0x6a: JUMP v217V6a(0x187)

    Begin block 0x21bB0x6a
    prev=[0x187B0x6a], succ=[0x73]
    =================================
    0x223S0x6a: JUMP v6b(0x73)

    Begin block 0x73
    prev=[0x21bB0x6a], succ=[0x2eb]
    =================================
    0x74: v74(0x40) = CONST 
    0x76: v76 = MLOAD v74(0x40)
    0x77: v77(0x20) = CONST 
    0x79: v79 = ADD v77(0x20), v76
    0x7a: v7a(0x83) = CONST 
    0x7f: v7f(0x2eb) = CONST 
    0x82: JUMP v7f(0x2eb)

    Begin block 0x2eb
    prev=[0x73], succ=[0x2f2]
    =================================
    0x2ec: v2ec(0x0) = CONST 
    0x2ef: v2ef = MLOAD v15aV6a
    0x2f0: v2f0(0x0) = CONST 

    Begin block 0x2f2
    prev=[0x2fb, 0x2eb], succ=[0x2fb, 0x30c]
    =================================
    0x2f2_0x0: v2f2_0 = PHI v2f0(0x0), v307
    0x2f5: v2f5 = LT v2f2_0, v2ef
    0x2f6: v2f6 = ISZERO v2f5
    0x2f7: v2f7(0x30c) = CONST 
    0x2fa: JUMPI v2f7(0x30c), v2f6

    Begin block 0x2fb
    prev=[0x2f2], succ=[0x2f2]
    =================================
    0x2fb: v2fb(0x20) = CONST 
    0x2fb_0x0: v2fb_0 = PHI v2f0(0x0), v307
    0x2ff: v2ff = ADD v15aV6a, v2fb_0
    0x301: v301 = ADD v2fb(0x20), v2ff
    0x302: v302 = MLOAD v301
    0x305: v305 = ADD v2fb_0, v79
    0x306: MSTORE v305, v302
    0x307: v307 = ADD v2fb(0x20), v2fb_0
    0x308: v308(0x2f2) = CONST 
    0x30b: JUMP v308(0x2f2)

    Begin block 0x30c
    prev=[0x2f2], succ=[0x315, 0x31b]
    =================================
    0x30c_0x0: v30c_0 = PHI v2f0(0x0), v307
    0x30f: v30f = GT v30c_0, v2ef
    0x310: v310 = ISZERO v30f
    0x311: v311(0x31b) = CONST 
    0x314: JUMPI v311(0x31b), v310

    Begin block 0x315
    prev=[0x30c], succ=[0x31b]
    =================================
    0x315: v315(0x0) = CONST 
    0x319: v319 = ADD v79, v2ef
    0x31a: MSTORE v319, v315(0x0)

    Begin block 0x31b
    prev=[0x315, 0x30c], succ=[0x83]
    =================================
    0x320: v320 = ADD v2ef, v79
    0x325: JUMP v7a(0x83)

    Begin block 0x83
    prev=[0x31b], succ=[0x326B0x83]
    =================================
    0x84: v84(0x40) = CONST 
    0x86: v86 = MLOAD v84(0x40)
    0x87: v87(0x20) = CONST 
    0x8b: v8b = SUB v320, v86
    0x8c: v8c = SUB v8b, v87(0x20)
    0x8e: MSTORE v86, v8c
    0x90: v90(0x40) = CONST 
    0x92: MSTORE v90(0x40), v320
    0x94: v94 = MLOAD v86
    0x96: v96(0x20) = CONST 
    0x98: v98 = ADD v96(0x20), v86
    0x99: v99 = SHA3 v98, v94
    0x9a: v9a(0x0) = CONST 
    0x9c: v9c(0x40) = CONST 
    0x9e: v9e = MLOAD v9c(0x40)
    0x9f: v9f(0x20) = CONST 
    0xa1: va1 = ADD v9f(0x20), v9e
    0xa2: va2(0xab) = CONST 
    0xa7: va7(0x326) = CONST 
    0xaa: JUMP va7(0x326)

    Begin block 0x326B0x83
    prev=[0x83], succ=[0x33cB0x83, 0x342B0x83]
    =================================
    0x327S0x83: v327V83(0x0) = CONST 
    0x32bS0x83: v32bV83 = SLOAD v9a(0x0)
    0x32dS0x83: v32dV83(0x1) = CONST 
    0x331S0x83: v331V83 = SHR v32dV83(0x1), v32bV83
    0x336S0x83: v336V83 = AND v32bV83, v32dV83(0x1)
    0x338S0x83: v338V83(0x342) = CONST 
    0x33bS0x83: JUMPI v338V83(0x342), v336V83

    Begin block 0x33cB0x83
    prev=[0x326B0x83], succ=[0x342B0x83]
    =================================
    0x33cS0x83: v33cV83(0x7f) = CONST 
    0x33fS0x83: v33fV83 = AND v331V83, v33cV83(0x7f)

    Begin block 0x342B0x83
    prev=[0x33cB0x83, 0x326B0x83], succ=[0x34fB0x83, 0x362B0x83]
    =================================
    0x342_0x2S0x83: v342_2V83 = PHI v33fV83, v331V83
    0x343S0x83: v343V83(0x20) = CONST 
    0x347S0x83: v347V83 = LT v342_2V83, v343V83(0x20)
    0x349S0x83: v349V83 = EQ v336V83, v347V83
    0x34aS0x83: v34aV83 = ISZERO v349V83
    0x34bS0x83: v34bV83(0x362) = CONST 
    0x34eS0x83: JUMPI v34bV83(0x362), v34aV83

    Begin block 0x34fB0x83
    prev=[0x342B0x83], succ=[]
    =================================
    0x34fS0x83: v34fV83(0x4e487b71) = CONST 
    0x354S0x83: v354V83(0xe0) = CONST 
    0x356S0x83: v356V83(0x4e487b7100000000000000000000000000000000000000000000000000000000) = SHL v354V83(0xe0), v34fV83(0x4e487b71)
    0x358S0x83: MSTORE v327V83(0x0), v356V83(0x4e487b7100000000000000000000000000000000000000000000000000000000)
    0x359S0x83: v359V83(0x22) = CONST 
    0x35bS0x83: v35bV83(0x4) = CONST 
    0x35dS0x83: MSTORE v35bV83(0x4), v359V83(0x22)
    0x35eS0x83: v35eV83(0x24) = CONST 
    0x361S0x83: REVERT v327V83(0x0), v35eV83(0x24)

    Begin block 0x362B0x83
    prev=[0x342B0x83], succ=[0x36aB0x83, 0x376B0x83]
    =================================
    0x365S0x83: v365V83 = ISZERO v336V83
    0x366S0x83: v366V83(0x376) = CONST 
    0x369S0x83: JUMPI v366V83(0x376), v365V83

    Begin block 0x36aB0x83
    prev=[0x362B0x83], succ=[0x372B0x83, 0x387B0x83]
    =================================
    0x36aS0x83: v36aV83(0x1) = CONST 
    0x36dS0x83: v36dV83 = EQ v336V83, v36aV83(0x1)
    0x36eS0x83: v36eV83(0x387) = CONST 
    0x371S0x83: JUMPI v36eV83(0x387), v36dV83

    Begin block 0x372B0x83
    prev=[0x36aB0x83], succ=[0x13fcB0x83]
    =================================
    0x372S0x83: v372V83(0x13fc) = CONST 
    0x375S0x83: JUMP v372V83(0x13fc)

    Begin block 0x13fcB0x83
    prev=[0x372B0x83], succ=[0xab]
    =================================
    0x1409S0x83: JUMP va2(0xab)

    Begin block 0xab
    prev=[0x13fcB0x83, 0x1429B0x83, 0x3b4B0x83], succ=[0xc7, 0x103]
    =================================
    0x83S0xab_0: vaa_0Vab_0 = PHI v327V83(0x0), v380V83, v3b1V83
    0xac: vac(0x40) = CONST 
    0xae: vae = MLOAD vac(0x40)
    0xaf: vaf(0x20) = CONST 
    0xb3: vb3 = SUB vaa_0Vab_0, vae
    0xb4: vb4 = SUB vb3, vaf(0x20)
    0xb6: MSTORE vae, vb4
    0xb8: vb8(0x40) = CONST 
    0xba: MSTORE vb8(0x40), vaa_0Vab_0
    0xbc: vbc = MLOAD vae
    0xbe: vbe(0x20) = CONST 
    0xc0: vc0 = ADD vbe(0x20), vae
    0xc1: vc1 = SHA3 vc0, vbc
    0xc2: vc2 = EQ vc1, v99
    0xc3: vc3(0x103) = CONST 
    0xc6: JUMPI vc3(0x103), vc2

    Begin block 0xc7
    prev=[0xab], succ=[]
    =================================
    0xc7: vc7(0x40) = CONST 
    0xc9: vc9 = MLOAD vc7(0x40)
    0xca: vca(0x461bcd) = CONST 
    0xce: vce(0xe5) = CONST 
    0xd0: vd0(0x8c379a000000000000000000000000000000000000000000000000000000000) = SHL vce(0xe5), vca(0x461bcd)
    0xd2: MSTORE vc9, vd0(0x8c379a000000000000000000000000000000000000000000000000000000000)
    0xd3: vd3(0x20) = CONST 
    0xd5: vd5(0x4) = CONST 
    0xd8: vd8 = ADD vc9, vd5(0x4)
    0xd9: MSTORE vd8, vd3(0x20)
    0xda: vda(0xe) = CONST 
    0xdc: vdc(0x24) = CONST 
    0xdf: vdf = ADD vc9, vdc(0x24)
    0xe0: MSTORE vdf, vda(0xe)
    0xe1: ve1(0x57726f6e67205472656173757265) = CONST 
    0xf0: vf0(0x90) = CONST 
    0xf2: vf2(0x57726f6e67205472656173757265000000000000000000000000000000000000) = SHL vf0(0x90), ve1(0x57726f6e67205472656173757265)
    0xf3: vf3(0x44) = CONST 
    0xf6: vf6 = ADD vc9, vf3(0x44)
    0xf7: MSTORE vf6, vf2(0x57726f6e67205472656173757265000000000000000000000000000000000000)
    0xf8: vf8(0x64) = CONST 
    0xfa: vfa = ADD vf8(0x64), vc9
    0xfb: vfb(0x40) = CONST 
    0xfd: vfd = MLOAD vfb(0x40)
    0x100: v100(0x64) = SUB vfa, vfd
    0x102: REVERT vfd, v100(0x64)

    Begin block 0x103
    prev=[0xab], succ=[0x4e]
    =================================
    0x105: v105(0x1) = CONST 
    0x108: v108 = SLOAD v105(0x1)
    0x109: v109(0xff) = CONST 
    0x10b: v10b(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00) = NOT v109(0xff)
    0x10c: v10c = AND v10b(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00), v108
    0x10e: v10e = OR v105(0x1), v10c
    0x110: SSTORE v105(0x1), v10e
    0x111: JUMP v3c(0x4e)

    Begin block 0x4e
    prev=[0x103], succ=[]
    =================================
    0x4f: STOP 

    Begin block 0x387B0x83
    prev=[0x36aB0x83], succ=[0x393B0x83]
    =================================
    0x388S0x83: v388V83(0x0) = CONST 
    0x38cS0x83: MSTORE v388V83(0x0), v9a(0x0)
    0x38dS0x83: v38dV83(0x20) = CONST 
    0x390S0x83: v390V83 = SHA3 v388V83(0x0), v38dV83(0x20)
    0x391S0x83: v391V83(0x0) = CONST 

    Begin block 0x393B0x83
    prev=[0x387B0x83, 0x39cB0x83], succ=[0x3acB0x83, 0x39cB0x83]
    =================================
    0x393_0x0S0x83: v393_0V83 = PHI v391V83(0x0), v3a7V83
    0x393_0x6S0x83: v393_6V83 = PHI v33fV83, v331V83
    0x396S0x83: v396V83 = LT v393_0V83, v393_6V83
    0x397S0x83: v397V83 = ISZERO v396V83
    0x398S0x83: v398V83(0x3ac) = CONST 
    0x39bS0x83: JUMPI v398V83(0x3ac), v397V83

    Begin block 0x3acB0x83
    prev=[0x393B0x83], succ=[0x3b4B0x83]
    =================================
    0x3ac_0x6S0x83: v3ac_6V83 = PHI v33fV83, v331V83
    0x3b1S0x83: v3b1V83 = ADD va1, v3ac_6V83

    Begin block 0x3b4B0x83
    prev=[0x3acB0x83], succ=[0xab]
    =================================
    0x3c1S0x83: JUMP va2(0xab)

    Begin block 0x39cB0x83
    prev=[0x393B0x83], succ=[0x393B0x83]
    =================================
    0x39c_0x0S0x83: v39c_0V83 = PHI v391V83(0x0), v3a7V83
    0x39c_0x1S0x83: v39c_1V83 = PHI v390V83, v3a4V83
    0x39dS0x83: v39dV83 = SLOAD v39c_1V83
    0x3a0S0x83: v3a0V83 = ADD v39c_0V83, va1
    0x3a1S0x83: MSTORE v3a0V83, v39dV83
    0x3a4S0x83: v3a4V83 = ADD v32dV83(0x1), v39c_1V83
    0x3a7S0x83: v3a7V83 = ADD v343V83(0x20), v39c_0V83
    0x3a8S0x83: v3a8V83(0x393) = CONST 
    0x3abS0x83: JUMP v3a8V83(0x393)

    Begin block 0x376B0x83
    prev=[0x362B0x83], succ=[0x1429B0x83]
    =================================
    0x376_0x4S0x83: v376_4V83 = PHI v33fV83, v331V83
    0x377S0x83: v377V83(0xff) = CONST 
    0x379S0x83: v379V83(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00) = NOT v377V83(0xff)
    0x37bS0x83: v37bV83 = AND v32bV83, v379V83(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00)
    0x37dS0x83: MSTORE va1, v37bV83
    0x380S0x83: v380V83 = ADD va1, v376_4V83
    0x383S0x83: v383V83(0x1429) = CONST 
    0x386S0x83: JUMP v383V83(0x1429)

    Begin block 0x1429B0x83
    prev=[0x376B0x83], succ=[0xab]
    =================================
    0x1436S0x83: JUMP va2(0xab)

}

function isSolved()() public {
    Begin block 0x50
    prev=[], succ=[]
    =================================
    0x51: v51(0x1) = CONST 
    0x53: v53 = SLOAD v51(0x1)
    0x54: v54(0xff) = CONST 
    0x56: v56 = AND v54(0xff), v53
    0x57: v57(0x40) = CONST 
    0x59: v59 = MLOAD v57(0x40)
    0x5b: v5b = ISZERO v56
    0x5c: v5c = ISZERO v5b
    0x5e: MSTORE v59, v5c
    0x5f: v5f(0x20) = CONST 
    0x61: v61 = ADD v5f(0x20), v59
    0x62: v62(0x40) = CONST 
    0x64: v64 = MLOAD v62(0x40)
    0x67: v67(0x20) = SUB v61, v64
    0x69: RETURN v64, v67(0x20)

}


```
</details>

里面是四个function

`__function_selector__` - 函数选择器，处理函数调用的入口点

`fallback()` - 回退函数，当调用不匹配任何函数时执行

`0x5cc4d812()` - 主要功能函数

`isSolved()` - 检查问题是否已解决的函数

这些和上面一样，有函数名不是被反编译的，而是他们的4字节签名已被记录

#### 分析0x5cc4d812

主要是看function 0x5cc4d812()

Tac基本就是分成一些block，而且本工具反编译的结构是线性的输出，也就是

```
Begin block 0x?? 开头
0x??: JUMPI 0x?? 结尾，跳到下一个block
```

整体执行的流程是这样的：

0x3b (函数入口) --> 0x23a (参数长度检查) --> 0x24c (字符串长度验证) --> 0x264 (调用数据长度检查) --> 0x278 (字符串长度验证) --> 0x28a (内存分配) --> 0x2b2 (字符串数据复制) --> 0x2cb (完成字符串加载) --> 0x49 (中间跳转) --> 0x6a (主处理开始) --> 0x112B0x6a (设置密钥 "key_77683056") --> 0x157B0x6a (初始化输出缓冲区) --> 0x181B0x6a (初始化循环计数器)

 

如何找到这个key，不借助ai，还挺难写，如果不是凭借我特别给出的`key_xxxx`格式的特点，还挺麻烦的


> 可以注意到(注意力惊人？)（实际上这么长的字符串一共就没有几个，所以是可以猜的）
>
> 0x130S0x6a: v130V6a(0x6b65795f37373638333035660000000000000000000000000000000000000000) = SHL v12eV6a(0xa1), v121V6a(0x35b2bcaf9b9b9b1c19981ab3)
>
> 中包含的 0x6b65795f37373638333035660000000000000000000000000000000000000000
>
> 解得即为：`key_7768305f`

#### 通过XOR反推

可以看到整个Tac中只有一个XOR操作，可以通过XOR操作反推来源

```assembly
// 从XOR操作开始逆向分析
0x1ddS0x6a: v1ddV6a = XOR v1dcV6a, v1bcV6a  // 输入字符 XOR 密钥字符

// 输入字符是如何获得的
0x1dcB0x6a: v1dcV6a = AND v1d7V6a(0xff), v1cfV6a  // 提取输入字符的单个字节
0x1d7B0x6a: v1d7V6a(0xff) = CONST 
0x1d6B0x6a: v1d6V6a = DIV v1cfV6a, v1d2V6a(0x100)
0x1d2B0x6a: v1d2V6a(0x100) = CONST 
0x1cfB0x6a: v1cfV6a = MLOAD v1ceV6a  // 从内存加载输入字符
0x1ceB0x6a: v1ceV6a = ADD v181V6a, v16aV6a  // 计算输入字符的内存位置

// 密钥字符是如何获得的
0x1bcB0x6a: v1bcV6a = AND v1baV6a(0xff), v1b2V6a  // 提取密钥字符的单个字节
0x1baB0x6a: v1baV6a(0xff) = CONST 
0x1b9B0x6a: v1b9V6a = DIV v1b2V6a, v1b5V6a(0x100)
0x1b5B0x6a: v1b5V6a(0x100) = CONST 
0x1b2B0x6a: v1b2V6a = MLOAD v1b1V6a  // 从内存加载密钥字符
0x1b1B0x6a: v1b1V6a = ADD v191V6a, v140V6a  // 计算密钥字符的内存位置
0x1aeB0x6a: v1aeV6a(0x1) = CONST 

// 密钥索引的计算
0x191B0x6a: v191V6a = MOD v181V6a, v11dV6a(0xc)  // 计算索引 = 循环计数器 % 密钥长度(12)

// 密钥在内存中的位置
0x140S0x6a: v140V6a = ADD v116V6a, v13dV6a(0x20)
0x13dS0x6a: v13dV6a(0x20) = CONST 

// 密钥存储到内存
0x141S0x6a: MSTORE v140V6a, v130V6a(0x6b65795f37373638333035660000000000000000000000000000000000000000)

// 密钥的硬编码值
0x130S0x6a: v130V6a(0x6b65795f37373638333035660000000000000000000000000000000000000000) = SHL v12eV6a(0xa1), v121V6a(0x35b2bcaf9b9b9b1c19981ab3)
0x12eS0x6a: v12eV6a(0xa1) = CONST 
0x121S0x6a: v121V6a(0x35b2bcaf9b9b9b1c19981ab3) = CONST 
```



总之是获得了xor用的值：`key_7768305f`*（这个key实际上是你flag的前四位的hex）*

还看到有些人的wp截断前12位为key，其实并非必要，`XOR 0`是没有影响的

### 正式解题

#### varg0

另一个值，在slot0

```
> eth.getStorageAt("0x63F6309C89827bA0176C592b1e348f479b5DaAd9")
"0x000000000000000000000000000000000000000000000000000000000000005d"
```

不太可能真的是0x5d，那说明数据长度超过32bytes了，被存到了数组中

> 在顺序存储中占据一整个插槽 slot index，其内容是该动态数组现在的`长度*2+1`
>
> 数组内容存储的开头是 slot keccak(index)

 （0x5d-1）/2=46，所以array的数据长度是46，占了两个slot



读一下，并XOR得到0x5cc4d812的参数 **varg0**

```python
from web3 import Web3
from eth_hash.auto import keccak
import sys

RPC_URL = "http://106.15.138.99:8545/"
CONTRACT_ADDR = "0x63F6309C89827bA0176C592b1e348f479b5DaAd9"
key = b"key_7768305f"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.isConnected():
    print("无法连接到 RPC:", RPC_URL)
    sys.exit(1)

slot0 = w3.eth.getStorageAt(CONTRACT_ADDR,0)
slot0_int = int.from_bytes(slot0, "big")

if slot0_int > 31:
    length = (slot0_int - 1)//2
    start_slot = int.from_bytes(keccak((0).to_bytes(32, "big")), "big")
    
    num_words = (length + 31) // 32
    data_bytes = b""
    for i in range(num_words):
        word = w3.eth.getStorageAt(CONTRACT_ADDR, start_slot + i)
        data_bytes += word
    data_bytes = data_bytes[:length]

recovered = bytes([data_bytes[i] ^ key[i % len(key)] for i in range(len(data_bytes))])

print(recovered.decode())
# 6534734845494c5f756e6433525f5448655f5345403f7d
```

这个varg0的结果unhex，会发现是flag的后半段，这只是为了让题目过程动态一些，防止串脚本



### 交互0x5cc4d812

没有源码，也没有ABI，只能直接构造CALLDATA了，我们底层一点，先试试手搓

#### CALLDATA

calldata 分为两个部分

```
[0x00..0x03]   函数选择器 (前 4 字节)
[0x04..]       参数编码
```

这个4bytes就是已知的5cc4d812

##### 静态类型

静态类型的长度固定，直接按 32 字节对齐编码。

| 类型                     | 编码方式举例                                |
| ------------------------ | ------------------------------------------- |
| `uint256(5)`             | `000...0005` （左填充 0，32 字节）          |
| `int256(-1)`             | `ff...ff` （补码，32 字节全 1）             |
| `address(0x1234...)`     | `000...001234...` （20 字节右对齐，前补 0） |
| `bool(true)`             | `000...001`                                 |
| `bool(false)`            | `000...000`                                 |
| `bytes32(0xdeadbeef...)` | 直接填入 32 字节，无需额外 padding          |

##### 动态类型

动态类型的编码更复杂：

**参数位置** = 一个 offset（相对整个参数区的起始位置，不含 4 字节 selector）。
 然后在 offset 指向的地方，写：

```
[length]   32 bytes
[data]     实际数据，右侧 padding 到 32 字节
```

典型动态类型有：

**`bytes`**

例如：`bytes("0x1234")`

```
参数区:  000...020   // offset = 0x20
数据区:  000...002   // length = 2
         123400...   // 内容 (2 字节)，右补零到 32
```

**`string`**

与 `bytes` 完全一样，只是默认 UTF-8。
 例如：`string("hi")` → 编码与 `bytes(0x6869)` 相同。

**动态数组**

如：`uint256[] [1,2,3]`

```
参数区:  offset=0x20
数据区:  length=3
         000..001
         000..002
         000..003
```





本题的参数就是bytes(实际上源码是string)

```
5cc4d812													//function selector
0000000000000000000000000000000000000000000000000000000000000020 //offset
000000000000000000000000000000000000000000000000000000000000002e //length
3635333437333438343534393463356637353665363433333532356635343438 //data
3635356635333435343033663764000000000000000000000000000000000000 //data+padding
```

然后就是怎么发calldata

用cast比较省事，通过remix ide也可以，或者web3.js/py，方法很多

```
0x52C733182320168157158ADEdd29F83F5F1156a6
```

```bash
cast send \
  --rpc-url "http://challenge.xinshi.fun:8545/" \
  --private-key "xxxxxxxxxxxxx" \
  "0x52C733182320168157158ADEdd29F83F5F1156a6" \
  "0x5cc4d8120000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002e36353334373334383435343934633566373536653634333335323566353434383635356635333435343033663764000000000000000000000000000000000000"
```

```
blockHash            0x17514bcc64d6152de86f1ebfaff3d262a24746aba5a17b28f7ef2ef0323782e2
blockNumber          16279
contractAddress
cumulativeGasUsed    70969
effectiveGasPrice    8
from                 0x3c0D8fA7C72ec83E293c21968Dd146BC43D431f5
gasUsed              70969
logs                 []
logsBloom            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root
status               1 (success)
transactionHash      0xc50475937b9fb9bb5412a5e76311795df19fa310a53e1ab06bb6355a511b92f4
transactionIndex     0
type                 2
blobGasPrice
blobGasUsed
to                   0x52C733182320168157158ADEdd29F83F5F1156a6
```



这是web3.py的版本

```python
from web3 import Web3

# 配置
w3 = Web3(Web3.HTTPProvider("http://challenge.xinshi.fun:8545/"))
private_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
account_address = "0x3c0D8fA7C72ec83E293c21968Dd146BC43D431f5"
contract_address = "0xff4D50B3dc7280DC32dA4174829c80cA661a905D"
calldata = "0x5cc4d8120000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002e36353334373334383435343934633566373536653634333335323566353434383635356635333435343033663764000000000000000000000000000000000000"

# 构建并发送交易
transaction = {
    'to': contract_address,
    'value': 0,
    'gas': 200000,
    'gasPrice': w3.eth.gasPrice,
    'nonce': w3.eth.getTransactionCount(account_address),
    'data': calldata,
    'chainId': w3.eth.chainId
}

# 签名并发送
signed_txn = w3.eth.account.signTransaction(transaction, private_key)
tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
print(f"交易哈希: {tx_hash.hex()}")

# 等待确认
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f"交易状态: {'成功' if receipt.status == 1 else '失败'}")
```

#### 辅助构造

手动构造不太优雅，可以借助abi encoder来构造calldata

```python
from web3 import Web3
from eth_abi import encode

RPC_URL = "http://challenge.xinshi.fun:8545/"
PRIVATE_KEY = "xxxxxxxxxxxxxxx"
ACCOUNT_ADDRESS = "0x3c0D8fA7C72ec83E293c21968Dd146BC43D431f5"
CONTRACT_ADDRESS = "0xff4D50B3dc7280DC32dA4174829c80cA661a905D"

SELECTOR_HEX = "0x5cc4d812"

PAYLOAD = "6534734845494c5f756e6433525f5448655f5345403f7d"


def ensure_hex_0x(s: str) -> str:
    s = s.strip()
    return s if s.startswith("0x") else "0x" + s

def main():
    # 连接节点
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.isConnected(), "RPC 连接失败，请检查 RPC_URL"

    sender = Web3.toChecksumAddress(ACCOUNT_ADDRESS)
    contract = Web3.toChecksumAddress(CONTRACT_ADDRESS)

    # 构造 selector（4 字节）
    selector = bytes.fromhex(ensure_hex_0x(SELECTOR_HEX)[2:])
    assert len(selector) == 4, "SELECTOR 必须是 4 字节（8 个十六进制字符）"

    # params = encode( ["string"], [PAYLOAD])
    params = encode( ["bytes"], [PAYLOAD.encode()])
    calldata = selector + params
    print(f"{calldata.hex()=}")

    # 构造交易
    nonce = w3.eth.getTransactionCount(sender)
    chain_id = w3.eth.chainId

    # 这里使用 legacy gasPrice；如需 EIP-1559，可换成 maxFeePerGas / maxPriorityFeePerGas
    tx = {
        "chainId": chain_id,
        "nonce": nonce,
        "to": contract,
        "value": 0,
        "gas": 200000,  # 可视情况上调或用 estimate_gas
        "gasPrice": w3.toWei("1", "gwei"),
        "data": calldata,
    }

    # 签名并发送
    signed = w3.eth.account.sign_transaction(tx, private_key=ensure_hex_0x(PRIVATE_KEY))
    tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
    print(f"已发送交易: {w3.toHex(tx_hash)}")

    # 等待回执（可注释掉）
    receipt = w3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
    print(f"交易状态 status={receipt.status}, gasUsed={receipt.gasUsed}")

    # 调 isSolved() 查看是否通过
    is_solved_selector = Web3.keccak(text="isSolved()")[:4]
    ret = w3.eth.call({
        "to": contract,
        "data": is_solved_selector
    })
    # 返回是 32 字节 bool
    solved = int.from_bytes(ret, byteorder="big") != 0
    print(f"isSolved(): {solved}")

if __name__ == "__main__":
    main()

```

### 其他

#### 合约源码

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;
contract OysterTreasure {

    string private encryptedTreasure;
    bool private treasureUnlocked;

    constructor(string memory treasure) {
        encryptedTreasure = _xorWithOysterKey(treasure);
        treasureUnlocked = false;
    }

    function _xorWithOysterKey(string memory text) internal pure returns (string memory) {
        bytes memory textBytes = bytes(text);
        bytes memory key = bytes("shenghuo2");
        bytes memory result = new bytes(textBytes.length);

        for (uint256 i = 0; i < textBytes.length; i++) {
            result[i] = bytes1(uint8(textBytes[i]) ^ uint8(key[i % key.length]));
        }

        return string(result);
    }

    function unlockOysterTreasure(string memory attempt) public {
        require(
            keccak256(abi.encodePacked(encryptedTreasure)) ==
            keccak256(abi.encodePacked(_xorWithOysterKey(attempt))),
            "Wrong Treasure"
        );
        treasureUnlocked = true;
    }

    function isSolved() public view returns (bool) {
        return treasureUnlocked;
    }
}
```