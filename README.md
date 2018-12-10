# CsharpUtil

## Welcome to CsharpUtil!

CsharpUtil is a tool box for C# developer,it contains:

- RSAUtil
- cmdProcess
- FilesUtil
- StartWhenOStartUtil
- iniUtil
- portUtil
- ipUtil
- xmlUtil
- SysEnvironment

## Build

Clone this repository,open CsharpUtil.sln and build

## Install

### NuGet Gallery

- [NuGet Gallery: CsharpUtil](https://www.nuget.org/packages/CsharpUtil/)

You can add CsharpUtil to your project with the NuGet Package Manager, by using the following command in the Package Manager Console.

```
PM> Install-Package CsharpUtil -Version 1.0.0
```

## Usage

### RSAUtil

RSAUtil contains :

- Encrypt
- Decrypt

```
using CsharpUtil.SystemUtil.RSAUtil;

//Encrypt
string publicKey = "Your public key";
string privateKey = "Your private key";
string content = "Your content for Encrypt";
RSAHelper rsaHepler = new RSAHelper(RSAType.RSA2, Encoding.UTF8, privateKey, publicKey);
string encryptedContent = rsaHepler.Encrypt(content);

//Decrypt
string sourceContent = rsaHepler.Decrypt(encryptedContent);
```

### cmdProcess

cmdProcess contains :

- Run a executable file and get output,finally kill the file in the timeout.

```
using CsharpUtil.SystemUtil.cmdProcess;

cmdProcess cmd = new cmdProcess();
string out = cmd.Run(@"C:\example.exe",1000); //out is the output of exapmle.exe 
```

-  Run a command string and return the pid of this cmd.

```
using CsharpUtil.SystemUtil.cmdProcess;

cmdProcess cmd = new cmdProcess();
int cmdPid = cmd.Run(@"start C:\example.exe");  //cmdPid is the pid of cmd
```

- Kill process and its children process.

```
using CsharpUtil.SystemUtil.cmdProcess;

cmdProcess.KillProcessAndChildren(8989); //8989 is the pid of process which you want to kill.
```

- Kill process.

```
using CsharpUtil.SystemUtil.cmdProcess;

cmdProcess.killProcessByPid(8989); //8989 is the pid of process which you want to kill.
```

- Use cmd to run a command string and return the pid of this cmd.

```
using CsharpUtil.SystemUtil.cmdProcess;

int cmdPid = cmdProcess.useStringToRunCmd(@"start C:\example.exe",true);
//"start C:\example.exe" is the string which you want cmd to run. true has no effect.
//cmdPid is the pid of this cmd
```

- Use cmd to run a command string and return the output of this cmd.

```
using CsharpUtil.SystemUtil.cmdProcess;

string output = cmdProcess.useStringToRunCmd(@"start C:\example.exe");
//"start C:\example.exe" is the string which you want cmd to run.
//output is the output of this cmd
```

- Use cmd to run a bat file ,and return the pid of this cmd.

```
using CsharpUtil.SystemUtil.cmdProcess;

int cmdPid = cmdProcess.RunBat(@"C:\example.bat");
//"C:\example.exe" is the path of the bat which you want to run. 
//cmdPid is the pid of this cmd
```

- check whether process of pid is exists or not.

```
using CsharpUtil.SystemUtil.cmdProcess;

bool result = cmdProcess.PidExists(8989);
//8989 is the pid which you want to check.
//result is true is it exists,otherwise else.
```

- Kill the process which is occupying the specified file.

```
using CsharpUtil.SystemUtil.cmdProcess;

cmdProcess.killProcessOfFile(@"C:\example.dll");
```

- get the pid of process which is occupying the specified file.

```
using CsharpUtil.SystemUtil.cmdProcess;

int resPid = cmdProcess.findProcessOfFile(@"C:\example.dll");
```

- Kill the process by the name of the process.

```
using CsharpUtil.SystemUtil.cmdProcess;

cmdProcess.killProcessByProcessName(@"java");
//kill java.exe
```

- Get the pid of process which is occupying the specified port.

```
using CsharpUtil.SystemUtil.cmdProcess;

int resPid = cmdProcess.findPidofPort(1080);
```

### FilesUtil

FilesUtil contains

- Unzip all zips in the specified directory.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.unzipFiles(@"C:\example");
//C:\example is the specified directory
```

- Unzip zip file to the specified directory and delete this zip file.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.unzipFiles(@"C:\example\1.zip", @"C:\temp");
```

- Copy files from one dir to other dir.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.copyFiles(@"C:\example", @"C:\temp");
//copy files in c:\example to c:\temp
```

- Find the path of file which has the specified suffix and in the specified directory.

```
using CsharpUtil.SystemUtil.FilesUtil;

string filePath = FilesUtil.findFilePathBySuffix(@"C:\exampleDir", @"exe");
//find the exe file in the C:\exampleDir
```

- Search file in the specified directory and return its fullPath.

```
using CsharpUtil.SystemUtil.FilesUtil;

string filePath = FilesUtil.findFilePathByName(@"C:\exampleDir", @"example.exe");
//find the exe file in the C:\exampleDir and its children directory
```

- add one line in the file start position.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.addFirstLine("example", @"C:\example.txt");
//add "example" in the start position of C:\example.txt
```

- add one line in the file end position.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.addEndLine("example", @"C:\example.txt");
//add "example" in the end position of C:\example.txt
```

- delete the first line of the file by file line content.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.deleteFirstLine("example", @"C:\example.txt");
//delete "example" in the start position of C:\example.txt if it is "example"
```

- Change the specified line of a file to another content.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.deleteFirstLine("example",2, @"C:\example.txt");
//change the 2 line content of  C:\example.txt to "example"
```

- Change the specified lines content of a file  to other content

```
using CsharpUtil.SystemUtil.FilesUtil;

string []LineContent = { "1", "2"};
int []linesIndex = { 3, 4};
FilesUtil.deleteFirstLine(LineContent,linesIndex, @"C:\example.txt");
//change the 3,4 line content of  C:\example.txt to "1" and "2"
```

- Delete the last line of a file.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.deleteEndLine("C:\example.txt");
```

- delete the specified line of a file by this line's content.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.deleteOneLine("example content","C:\example.txt");
```

- Update file contents or create a file use specifed content if it not exists.

```
using CsharpUtil.SystemUtil.FilesUtil;

List<string> content = new List<string>();
content.Add("example");
FilesUtil.updateOrCreateByFileContent(content, @"C:\example.txt");
```

- Update file contents or create a file use specifed content if it not exists.

```
using CsharpUtil.SystemUtil.FilesUtil;

FilesUtil.updateOrCreateByFileContent("example", @"C:\example.txt");
```

### StartWhenOStartUtil

StartWhenOStartUtil contains:

- set executablefile start when system start.

```
using CsharpUtil.SystemUtil.StartWhenOStartUtil;

StartWhenOStartUtil.setStartWhenOsStart("C:/example.exe", "example");
//C:/example.exe is the executable and "example" is the service name ,you can created by your self.
```

- delete the executablefile start when system start.

```
using CsharpUtil.SystemUtil.StartWhenOStartUtil;

StartWhenOStartUtil.deletStartWhenOsStart("example");
//"example" is the service name which you set 
```

### iniUtil

iniUtil contains :

- read the value in the **.ini** file

```
//setup.ini:
/**
[example]
port=1255
path=/projects
*/

using CsharpUtil.SystemUtil.iniUtil;

string res = iniUtil.ReadIniData("example","port","","C:/setup.ini");
```

- write value in the **.ini** file

```
using CsharpUtil.SystemUtil.iniUtil;

string res = iniUtil.ReadIniData("example","port","1333","C:/setup.ini");
```

### portUtil

- find a port which is not occupied by other process.

```
using CsharpUtil.SystemUtil.portUtil;

int port = portUtil.findUsablePort();
```

- check a port is occupied or not 

```
using CsharpUtil.SystemUtil.portUtil;

bool res = portUtil.PortIsAvailable(1080);
//res is true if 1080 is not occupied.
```

### ipUtil

- get the machine ip

```
using CsharpUtil.SystemUtil.ipUtil;

string ip = ipUtil.GetLocalIPAddress();
```

### xmlUtil

### SysEnvironment

SysEnvironment contains :

- get system environment variable

```
using Csharputil.SystemUtil.SysEnvironment;

string res = SysEnvironment.GetSysEnvironmentByName("JAVA_PATH");
//get the "JAVA_PATH" environment varable
```

- set system environment variable

```
using Csharputil.SystemUtil.SysEnvironment;

SysEnvironment.SetSysEnvironment("JAVA_PATH","c:/java");
//set the "JAVA_PATH" environment varable
```

- check whether system environment variable is exists

```
using Csharputil.SystemUtil.SysEnvironment;

bool res = SysEnvironment.CheckSysEnvironmentExist("JAVA_PATH");
```

- set "PATH" environment variable

```
using Csharputil.SystemUtil.SysEnvironment;

bool res = SysEnvironment.CheckSysEnvironmentExist("C:/java");	
```