# StartVTXHookDriverFromNone
从0开始编写Windows Intel VT-X Hook 驱动的个人项目
## 进度
VT EPT HOOK 完成  
集成Intel XED库，可以识别函数指令长度方便HOOK  
可以通过VMP3.x检测（和我的AMD VT共用了很多代码，这个还没测试）  
## 编译环境
VS222 + WDK 10
## 测试环境
Windows 11 24H2  
Windows 10 22h2  
## 联系（其实就是催更方式）
邮箱：1103660629@qq.com  
QQ：1103660629  
## 推荐项目（现在我学习的就这个）
https://github.com/DarthTon/HyperBone  
https://github.com/jonomango/hv  
## 引用的库
Intel XED https://github.com/intelxed/xed 修改见 StartAMDVHookDriverFromNone 项目的 XED Information 文件夹
## 如何使用SDK调用驱动功能
见FunctionTest.cpp  
## 暂停开发
本人需要准备考试，明年6月再开发