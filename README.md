# FridaWindowsAPILogger
使用frida hook windows api
1. 自定义hook列表(hookConfig)
2. 自定义hook规则(hookGenericFunction)
3. 程序的API调用行为最终会存放在目录下frida_log.txt文件中
相较于Android,frida当前在exe中的对抗烈度还是低的
对于反调试,目前测试的GetTickCount可以检测出来,因此也对应做了处理
