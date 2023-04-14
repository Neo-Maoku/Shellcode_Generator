# Shellcode_Generator
一键生成windows x86 shellcode的python脚本

## 📖目录

* [👨🏻‍💻  预览演示](#-预览演示)
* [🔥 介绍](#-介绍)
* [🔗 使用环境](#-使用环境)
* [💡用法 Usage](#-用法-usage)
* [📜 版权与免责声明](#-版权与免责声明)

## 👨🏻‍💻 预览演示

![screenshots](.\res\screenshots.gif)

## 🔥 介绍

​	本项目主要想解决手动编写shellcode的过程中痛点问题（**全局变量**、**重定位**、**系统API调用**等），帮助用户使用**C/C++**实现的方法一键转换成shellcode。

### 优点和不足之处

---

**优点：**

- 大胆使用全局变量和系统API，再也不用担心地址重定位问题

- 不局限于MSF和CS提供shellcode模板、随意发挥。

- 支持嵌套使用shellcode

**不足：**

- 暂不支持x64的shellcode生成
- 对于有些VC运行时的函数处理不了，比如strtok函数

## 🔗使用环境

- 项目目前仅支持生成**x86**的shellcode

- 需要安装**IDA**软件并支持运行**python**脚本

- 使用VS编译项目时需要**禁用优化**并把代码生成设置为**多线程/MT**

## 💡用法 Usage

1. 打开VS项目，在Shellcode_Generator_Demo.c文件中的strat函数处添加需要生成的shellcode代码，编译项目
2. 使用IDA打开编译好的程序，一路默认选项，可参考演示实例
3. 在IDA中找到main函数，光标选中main函数内任意地址
4. 按下快捷键ALT+F7，选择项目中ida_shellcode_generator.py脚本
5. 运行结束后会生成一个shellcode文件路径和大小，可以生成raw或txt格式（需要修改脚本中的outType）
6. 可以使用Shellcode_Generator_Demo.c中的testShellcodeRun方法测试shellcode是否可用

