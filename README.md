# Shellcode_Generator

![Language](https://img.shields.io/badge/language-c-blue.svg) ![Language](https://img.shields.io/badge/language-python-blue.svg) [![GitHub License](https://img.shields.io/github/license/jxust-xiaoxiong/Shellcode_Generator.svg)](https://github.com/jxust-xiaoxiong/Shellcode_Generator) [![GitHub Stars](https://img.shields.io/github/stars/jxust-xiaoxiong/Shellcode_Generator.svg)](https://github.com/jxust-xiaoxiong/Shellcode_Generator/stargazers)

一键生成windows x86 shellcode的python脚本

## 📖目录

* [👨🏻‍💻 预览演示](#-预览演示)
* [🔥 介绍](#-介绍)
* [🔗 使用环境](#-使用环境)
* [💡 用法](#-用法)
* [🔩 设计思路](#-设计思路)
* [🔨 Issue提交说明](#-Issue提交说明)
* [📜 版权与免责声明](#-版权与免责声明)

## 👨🏻‍💻 预览演示

演示生成的shellcode代码功能为创建regedit进程，向regedit进程远程线程注入添加自启动注册表项完成持久化功能。
![screenshots](./res/screenshots.gif)

## 🔥 介绍

​	本项目主要想解决手动编写shellcode的过程中痛点问题（**全局变量**、**重定位**、**Windows API调用**等），帮助用户使用**C语言**实现的方法一键转换成shellcode。

### 优点和不足之处

---

**优点：**

- 使用简单方便，对于shellcode编写不熟练的用户，使用它可以大大提高效率
- 大胆使用全局变量和系统API，再也不用担心地址重定位问题
- 不局限于MSF和CS提供shellcode模板、随意发挥。
- 支持嵌套使用shellcode

**不足：**

- 暂不支持x64的shellcode生成。
- 对于有些**C标准库函数**处理不了，比如**strtok**函数。
- 生成的shellcode长度会比手动编写的长不少，但相对于ReflectiveLoader反射加载的长度小很多。

## 🔗 使用环境

- 项目目前仅支持生成**x86**的shellcode
- 需要安装**IDA**软件并支持运行**python**脚本
- 使用VS编译项目时需要**禁用优化**并把代码生成设置为**多线程/MT**
- 能使用**Windows API**和**C标准库函数**完成功能时，优先使用Windows API，可以减少大量系统依赖。比如**exit**和**ExitProcess**可以实现结束进程，优先使用**ExitProcess**方法。

## 💡 用法

1. 打开VS项目，在Shellcode_Generator_Demo.c文件中的strat函数处添加需要生成的shellcode代码，编译项目

2. 使用IDA打开编译好的程序，一路默认选项，可参考演示实例

3. 在IDA中找到main函数，光标选中main函数内任意地址

4. 按下快捷键ALT+F7，选择项目中ida_shellcode_generator.py脚本

5. 运行结束后会生成一个shellcode文件路径和大小，可以生成raw或txt格式（需要修改脚本中的outType）

6. 可以使用Shellcode_Generator_Demo.c中的testShellcodeRun方法测试shellcode是否可用

## 🔩 设计思路

**python脚本：**

1. 输入启动函数的地址，递归遍历所有被调用的函数写入shellcode
2. 修复shellcode中函数体的调用指令的偏移操作数
3. 在shellcode去除security_check相关内容（替换为nop）
4. 拷贝全局变量和已初始化变量到shellcode末尾
5. 构造IAT的字符串数据到shellcode末尾，替换C代码中**iatInfoOffset**变量值
6. 构造IAT表到shellcode末尾，修复IAT表中的函数调用偏移，替换C代码中**iatBeginOffset**变量值
7. 构造重定位表到shellcode末尾，修复重定位数据的引用偏移，替换C代码中**relocBeginOffset和relocEndOffset**变量值
8. 输出shellcode到指定文件格式，打印输出路径和shellcode长度

**C文件：**

1. 获取shellcode所在的基址
2. 根据relocBeginOffset变量判断是否有重定位信息需要修复，有的话就根据基址和重定位表修复
3. 根据iatInfoOffset变量判断是否有IAT表需要修复，不需要修复时直接跳转到用户定义的start函数
4. 需要修复IAT表时，需要先通过汇编代码获取到GetProcAddress、GetModuleHandle等方法
5. 根据iatInfoOffset存放的IAT的字符串信息依次修复IAT表
6. 跳转到用户定义的start函数执行

## 🔨 Issue提交说明

- 脚本运行时报错，欢迎提交程序的IDA文件帮助定位问题，要是能提供代码源文件更好了。
- IDA程序无法运行Python脚本时，请自行google搜索相关解决方案。

## 📜 版权与免责声明

### 版权 

该项目签署了GPL-3.0授权许可，详情请参阅[Licence](https://raw.githubusercontent.com/jxust-xiaoxiong/Shellcode_Generator/master/Licence)。![gplv3](http://www.gnu.org/graphics/gplv3-or-later.png)

 除此之外也需要遵守项目中如下的补充条款：

 该项目未经作者本人允许，禁止商业使用。

 任何人不得将其用于非法用途及盈利等目的，否则自行承担后果并负相应法律责任。

### 免责声明

1. 本工具仅面向拥有合法授权的渗透测试安全人员及进行常规操作的网络运维人员，用户可在取得足够合法授权且非商用的前提下进行下载、复制、传播或使用。
2. 在使用本工具的过程中，您应确保自己的所有行为符合当地法律法规，且不得将此软件用于违反中国人民共和国相关法律的活动。本工具所有作者和贡献者不承担用户擅自使用本工具从事任何违法活动所产生的任何责任。

请您在下载并使用本工具前，充分阅读、完全理解并接受本协议的所有条款。您的使用行为或您以其他任何方式明示或默认表示接受本协议，即视为您已阅读并同意本协议的约束。
