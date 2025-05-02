//文件存储路径
const LINK_BEFORE_PATH = "link_before.txt";   
const LOG_FILE_PATH = "frida_log.txt"; 

//---------------------Log格式---------------------
(function () {
    let Color = { RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", "Green": "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01" };
    let LightColor = { RESET: "\x1b[39;49;00m", Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", "Green": "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11" };
    var colorPrefix = '\x1b[3', colorSuffix = 'm'
    for (let c in Color) {
        if (c == "RESET") continue;
        console[c] = function (message) {
            console.log(colorPrefix + Color[c] + colorSuffix + message + Color.RESET);
        }
        console["Light" + c] = function (message) {
            console.log(colorPrefix + LightColor[c] + colorSuffix + message + Color.RESET);
        }
    }
})();
function writeLog(message) {   
    writeTextFile(LOG_FILE_PATH,message);   
    console.log(message); // 同时输出到控制台  
}  
//打印函数调用
function writeLogTitle(message) {  
    writeTextFile(LOG_FILE_PATH,message);  
    console.Green(message); // 同时输出到控制台  
}  
//打印查找失败
function writeLogFail(message) {  
    writeTextFile(LOG_FILE_PATH,message);  
    console.Red(message); // 同时输出到控制台  
}  
//动态链接调用强调色
function writeLogLink(message) {  
    writeTextFile(LOG_FILE_PATH,message);  
    console.Blue(message); // 同时输出到控制台  
}

//---------------------数据结构和对象-------------------
const hookConfig = {  
    "kernel32.dll": [  
        "VirtualAlloc",  
        "WriteProcessMemory",   
        "ReadFile",   
        "CreateFileA",   
        "CreateRemoteThread",  
        "VirtualAllocEx",  
        "WinExec",  
        "OpenProcess",
        "IsDebuggerPresent"
    ],  
    "ws2_32.dll": [  
        "send",  
        "connect"  
    ],  
    "advapi32.dll": [  
        "RegCreateKeyA",  
        "RegCreateKeyW",  
        "RegDeleteKeyA",   
        "RegDeleteKeyW",  
        "RegEnumKeyExA",  
        "RegEnumKeyExW",   
        "RegSetValueA",  
        "RegSetValueW",  
        "RegSetValueExA",   
        "RegSetValueExW"  
    ],
    "user32.dll":[
        "GetWindowThreadProcessId"
    ]  
};  
const LinkBefore = {  
    funcs: [],  
    has: function(moduleName, functionName) {  
        this.funcs = readTextFile(LINK_BEFORE_PATH);  
        // 将moduleName和functionName都转为小写  
        const key = `${moduleName.toLowerCase()}:${functionName.toLowerCase()}`;  
        for (const func of this.funcs) {
            if (func.trim() === key.trim()) {  
                return true;  
            }  
        }  
        return false;  
    },  
    add: function(moduleName, functionName) {  
        // 将moduleName和functionName都转为小写  
        const key = `${moduleName.toLowerCase()}:${functionName.toLowerCase()}`;  
        if (!this.has(moduleName, functionName)) {  // 使用改进的has函数  
            this.funcs.push(key);  // 使用push添加新函数  
            // 追加到文件  
            writeTextFile(LINK_BEFORE_PATH, key);  
        }  
    }   
};      


//---------------------辅助函数---------------------------------
//文件初始化/文件清空
function FileInit(filePath) {  
    const file = new File(filePath, "w");  
    file.close();  
    console.log(`[*] 创建文件: ${filePath}`);   
}  
// 读取文本文件  
function readTextFile(filePath) {  
    try {   
        const content = File.readAllText(filePath);  
        return content ? content.split('\n').filter(Boolean) : [];  // 返回每行数据作为一个数组  
    } catch(e) {  
        console.log(`读取文件 ${filePath} 失败: ${e}`);  
        return [];  
    }  
}  
// 写入文本文件（追加模式）  
function writeTextFile(filePath, newData) {  
    try {  
        const file = new File(filePath, "a+");  
        file.write(newData + '\n');  
        file.flush();
        file.close();  
    } catch(e) {  
        console.log(`写入文件 ${filePath} 失败: ${e}`);  
    }  
}  

function formatBuffer(buffer, maxLength = 100) {  
    if (!buffer) return "null";  
    try {  
        // 尝试UTF-8解码  
        let str = Memory.readUtf8String(buffer);  
        return str.length > maxLength   
            ? str.substring(0, maxLength) + "..."   
            : str;  
    } catch(e) {  
        // 如果不是文本，尝试转换为16进制  
        try {  
            const bufView = new Uint8Array(Memory.readByteArray(buffer, maxLength));  
            return Array.from(bufView)  
                .map(b => b.toString(16).padStart(2, '0'))  
                .join(' ');  
        } catch(e) {  
            return "无法解析";  
        }  
    }  
}  
function formatIPv4(ipBytes) {  
    var bytes = new Uint8Array(ipBytes);  
    return bytes[0] + '.' + bytes[1] + '.' + bytes[2] + '.' + bytes[3];  
}  
function isInterestingFunction(moduleName, functionName) {  
    // 规范化模块名（移除 .dll 后缀，转换为小写）  
    const normalizedModuleName = moduleName.toLowerCase().replace('.dll', '');  
    
    // 遍历 hookConfig 检查是否为感兴趣的函数  
    for (let configModule in hookConfig) {  
        const configModuleName = configModule.toLowerCase().replace('.dll', '');  
        
        if (normalizedModuleName === configModuleName) {  
            return hookConfig[configModule].includes(functionName);  
        }  
    }  
    return false;  
}  

//时间
var time_record_32 = 0;
var time_record_64 = 0;
function hookGetTickCount() {  
    const kernel32 = Module.findExportByName("kernel32.dll", "GetTickCount");  
    const kernel32_64 = Module.findExportByName("kernel32.dll", "GetTickCount64");  

    if (kernel32) {  
        Interceptor.attach(kernel32, {  
            onEnter: function(args) {
                writeLogTitle(`[时间检测] GetTickCount 调用`);
                // 获取调用地址并只选取最后一个地址  
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);  
                const callerAddress = backtrace[backtrace.length - 1];  // 取得最后一个地址  
                writeLogTitle(`[-] 调用地址: ${callerAddress}`);    
            },  
            onLeave: function(retval) {  
                if(time_record_32 == 0){
                    time_record_32 = retval.toInt32();
                }else{
                    retval.replace(time_record_32 + 1); // 返回值替换  
                    time_record_32 = retval.toInt32(); // 更新上一次返回值  
                }  
                writeLog(`¦- 返回值: ${retval}`);
                console.log();     
            }  
        });  
    }  
    if (kernel32_64) {  
        Interceptor.attach(kernel32_64, {  
            onEnter: function(args) { 
                writeLogTitle(`[时间检测] GetTickCount64 调用`);
                // 获取调用地址并只选取最后一个地址  
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);  
                const callerAddress = backtrace[backtrace.length - 1];  // 取得最后一个地址  
                writeLogTitle(`[-] 调用地址: ${callerAddress}`);   
            },  
            onLeave: function(retval) {  
                if(time_record_64 == 0){
                    time_record_64 = retval.toInt32();
                }else{
                    retval.replace(time_record_64 + 1); // 返回值替换  
                    time_record_64 = retval.toInt32(); // 更新上一次返回值  
                }
                // writeLogTitle(`[反调试] GetTickCount64 调用`);  
                writeLog(`¦- 返回值: ${retval}`); 
                console.log();     
            }  
        });  
    }
} 

//获取程序基地址
// 打印被调试程序主模块的基地址  
function printMainModuleBaseAddress() {  
    const modules = Process.enumerateModules();  
    for (let i = 0; i < modules.length; i++) {  
        const module = modules[i]; 
        if (module.name.indexOf('1.exe') !== -1) {  
            writeLogTitle(`[+] 被调试程序 '${module.name}' 基地址: 0x${module.base.toString(16)}`);
            console.log();     
            return;  
        }  
    }  
    writeLogFail(`[-] 未找到被调试程序的基地址`);    
}  

//---------------------根据指定规则hook指定函数 --------------------------------
function hookGenericFunction(moduleName, functionName) {
    const funcAddr = Module.findExportByName(moduleName, functionName);  
    if (funcAddr) {  
        Interceptor.attach(funcAddr, {  
            onEnter: function(args) {  
                writeLogTitle(`[+] ${moduleName}!${functionName} 被调用`);  
                // 获取调用地址并只选取最后一个地址  
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);  
                const callerAddress = backtrace[backtrace.length - 1];  // 取得最后一个地址  
                writeLogTitle(`[-] 调用地址: ${callerAddress}`);  
                try {  
                    switch(functionName) {  
                        case "IsDebuggerPresent":{
                            break;
                        }
                        case "VirtualAlloc":  
                        case "VirtualAllocEx": {  
                            writeLog(`地址: ${args[0]}`);  
                            writeLog(`大小: ${args[1]}`);  
                            writeLog(`分配类型: ${args[2]}`);  
                            writeLog(`保护类型: ${args[3]}`);  
                            break;  
                        }  
                        case "WriteProcessMemory": {  
                            writeLog(`目标进程句柄: ${args[0]}`);  
                            writeLog(`目标地址: ${args[1]}`);  
                            writeLog(`写入内容: ${formatBuffer(args[2])}`);  
                            writeLog(`写入大小: ${args[3]}`);  
                            break;  
                        }        
                        case "ReadFile": {  
                            writeLog(`文件句柄: ${args[0]}`);  
                            writeLog(`缓冲区: ${args[1]}`);  
                            writeLog(`读取大小: ${args[2]}`);  
                            break;  
                        }  
                        case "CreateFileA": {  
                            try {  
                                // 安全地读取文件名  
                                var fileName = args[0] ? Memory.readAnsiString(args[0]) : "未知文件";  
                                writeLog("¦- 文件名: " + fileName);  
                                
                                // 安全地处理访问权限  
                                var desiredAccess = args[1] ? args[1].toInt32() : 0;  
                                writeLog("¦- 所需访问权限: " + desiredAccess);  
                                
                                // 额外的参数信息  
                                writeLog("¦- 共享模式: " + (args[2] ? args[2].toInt32() : 0));  
                                writeLog("¦- 安全属性: " + args[3]);  
                                writeLog("¦- 创建方式: " + (args[4] ? args[4].toInt32() : 0));  
                                writeLog("¦- 文件属性: " + (args[5] ? args[5].toInt32() : 0));  
                            } catch (e) {  
                                writeLogFail("[-] CreateFile 参数解析错误: " + e.message);  
                            } 
                            break;  
                        }  
                        case "send": {  
                            writeLog(`Socket: ${args[0]}`);  
                            writeLog(`发送数据: ${formatBuffer(args[1], 200)}`);  
                            writeLog(`数据长度: ${args[2]}`);  
                            break;  
                        }  
                        case "connect": {  
                            try {  
                                writeLog("¦- 套接字: " + args[0]);  
                                    
                                // 获取 sockaddr 结构体指针和长度  
                                var sockaddrPtr = args[1];  
                                var addrLen = args[2].toInt32();  
                                    
                                // 安全地读取地址族  
                                var addressFamily = Memory.readU16(sockaddrPtr);  
                                writeLog("¦- 地址族: " + addressFamily);  
                                    
                                // 仅处理 IPv4 地址 (AF_INET = 2)  
                                if (addressFamily === 2) {  
                                    // 读取端口（网络字节序，需要转换）  
                                    var portRaw = Memory.readU16(sockaddrPtr.add(2));  
                                    var port = ((portRaw & 0xFF) << 8) | ((portRaw >> 8) & 0xFF);  
                                    writeLog("¦- 端口: " + port);  
                                        
                                    // 读取IP地址  
                                    var ipBytes = Memory.readByteArray(sockaddrPtr.add(4), 4);  
                                    var ipAddress = formatIPv4(ipBytes);  
                                    writeLog("¦- IP地址: " + ipAddress);  
                                } else {  
                                    writeLog("¦- 非IPv4地址族: " + addressFamily);  
                                }  
                            } catch (e) {  
                                writeLogFail("[-] 解析地址时发生错误: " + e.message);  
                            } 
                            break;  
                        }              
                        case "RegCreateKeyA":  
                        case "RegCreateKeyW":  
                        case "RegDeleteKeyA":  
                        case "RegDeleteKeyW": {  
                            const keyName = Memory.readAnsiString(args[1]);  
                            writeLog(`注册表键名: ${keyName}`);  
                            break;  
                        }                   
                        case "RegEnumKeyExA":  
                        case "RegEnumKeyExW": {  
                            writeLog(`注册表句柄: ${args[0]}`);  
                            writeLog(`索引: ${args[1]}`);  
                            break;  
                        }                    
                        case "RegSetValueA":  
                        case "RegSetValueW":  
                        case "RegSetValueExA":  
                        case "RegSetValueExW": {  
                            const valueName = Memory.readAnsiString(args[2]);  
                            writeLog(`注册表值名: ${valueName}`);  
                            writeLog(`数据: ${formatBuffer(args[3])}`);  
                            break;  
                        }                   
                        case "CreateRemoteThread": {  
                            writeLog(`目标进程句柄: ${args[0]}`);  
                            writeLog(`线程入口地址: ${args[2]}`);  
                            writeLog(`线程参数: ${args[3]}`);  
                            break;  
                        }       
                        case "OpenProcess": {  
                            writeLog(`进程ID: ${args[2]}`);  
                            break;  
                        }              
                        case "GetWindowThreadProcessId": {  
                            writeLog(`窗口句柄: ${args[0]}`);  
                            break;  
                        }             
                        case "WinExec": {  
                            const cmdLine = Memory.readAnsiString(args[0]);  
                            writeLog(`执行命令: ${cmdLine}`);  
                            break;  
                        }    
                        default: {  
                            // 通用参数处理  
                            for (let i = 0; i < args.length; i++) {  
                                writeLog(`参数 ${i}: ${args[i]}`);  
                            }  
                        }  
                    }
                } catch(e) {  
                    writeLogFail(`处理参数时发生错误: ${e}`);  
                }
            },  
            onLeave: function(retval) {  
                writeLogTitle(`[-] ${moduleName}!${functionName} 返回值: ${retval}`);
                console.log();     
            }  
        });  
        writeLogTitle(`[*] 成功 Hook ${moduleName}!${functionName}`);
        LinkBefore.add(moduleName,functionName);    
    } else {  
        writeLogFail(`[-] 无法找到 ${moduleName}!${functionName},配置文件错误或dll存在异常`);  
    }  
}  

//--------------------动态链接函数hook------------------------  
function hookGetProcAddress() {  
    const GetProcAddress = Module.findExportByName("kernel32.dll", "GetProcAddress");  
    if (GetProcAddress) {  
        Interceptor.attach(GetProcAddress, {  
            onEnter: function(args) {  
                const moduleHandle = args[0];  
                const functionName = Memory.readAnsiString(args[1]);  
                // 获取调用地址并只选取最后一个地址  
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);  
                const callerAddress = backtrace[backtrace.length - 1];  // 取得最后一个地址 
                // 尝试获取模块名称  
                const moduleInfo = Process.getModuleByAddress(moduleHandle);  
                const moduleName = moduleInfo ? moduleInfo.name : "未知模块";  
                

                writeLogLink(`[*] GetProcAddress 被调用`); 
                writeLogTitle(`[-] 调用地址: ${callerAddress}`);  
                writeLog(`¦- 模块句柄: ${moduleHandle}`);  
                writeLog(`¦- 模块名称: ${moduleName}`);  
                writeLog(`¦- 函数名称: ${functionName}`);
                if(isInterestingFunction(moduleName,functionName) && !(LinkBefore.has(moduleName,functionName))) {
                    hookGenericFunction(moduleName,functionName);
                }
            },  
            onLeave: function(retval) {  
                if (retval && !retval.isNull()) { 
                    writeLog(`[*] 函数地址: ${retval}`);
                    console.log("/n");    
                }  
            }  
        });  
        writeLogTitle("[*] 成功 Hook GetProcAddress");  
    } else {  
        writeLogFail("[-] 无法 Hook GetProcAddress");  
    }  
}   

//---------------------入口------------------------------------
function main() {  
    //文件初始化
    FileInit(LINK_BEFORE_PATH);  
    FileInit(LOG_FILE_PATH);  
    printMainModuleBaseAddress();
    hookGetProcAddress();
    //反反调试
    hookGetTickCount(); 
    // 预先 Hook 配置中的模块  
    for (let moduleName in hookConfig) {  
        hookConfig[moduleName].forEach(funcName => {  
            hookGenericFunction(moduleName, funcName);  
        });  
    } 
}  

setImmediate(main);  