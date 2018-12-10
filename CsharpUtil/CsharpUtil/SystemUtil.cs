using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Net.NetworkInformation;
using System.Net;
using System.Collections;
using System.Text.RegularExpressions;
using System.Xml;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Linq;

namespace CsharpUtil
{    
    /**
        * 一些实用的工具
        * */
    public class SystemUtil
    {
        //encrypt and decode tools
        public class RSAUtil
        {
            /// <summary>
            /// RSA加解密 使用OpenSSL的公钥加密/私钥解密
            /// 
            /// 公私钥请使用openssl生成  ssh-keygen -t rsa 命令生成的公钥私钥是不行的            
            public class RSAHelper
            {
                private readonly RSA _privateKeyRsaProvider;
                private readonly RSA _publicKeyRsaProvider;
                private readonly HashAlgorithmName _hashAlgorithmName;
                private readonly Encoding _encoding;

                /// <summary>
                /// 实例化RSAHelper
                /// </summary>
                /// <param name="rsaType">加密算法类型 RSA SHA1;RSA2 SHA256 密钥长度至少为2048</param>
                /// <param name="encoding">编码类型</param>
                /// <param name="privateKey">私钥</param>
                /// <param name="publicKey">公钥</param>
                public RSAHelper(RSAType rsaType, Encoding encoding, string privateKey, string publicKey = null)
                {
                    _encoding = encoding;
                    if (!string.IsNullOrEmpty(privateKey))
                    {
                        _privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
                    }

                    if (!string.IsNullOrEmpty(publicKey))
                    {
                        _publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publicKey);
                    }

                    _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
                }

                #region 使用私钥签名

                /// <summary>
                /// 使用私钥签名
                /// </summary>
                /// <param name="data">原始数据</param>
                /// <returns></returns>
                public string Sign(string data)
                {
                    byte[] dataBytes = _encoding.GetBytes(data);

                    var signatureBytes = _privateKeyRsaProvider.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);

                    return Convert.ToBase64String(signatureBytes);
                }

                #endregion

                #region 使用公钥验证签名

                /// <summary>
                /// 使用公钥验证签名
                /// </summary>
                /// <param name="data">原始数据</param>
                /// <param name="sign">签名</param>
                /// <returns></returns>
                public bool Verify(string data, string sign)
                {
                    byte[] dataBytes = _encoding.GetBytes(data);
                    byte[] signBytes = Convert.FromBase64String(sign);

                    var verify = _publicKeyRsaProvider.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);

                    return verify;
                }

                #endregion

                #region 解密

                public string Decrypt(string cipherText)
                {
                    if (_privateKeyRsaProvider == null)
                    {
                        throw new Exception("_privateKeyRsaProvider is null");
                    }
                    return Encoding.UTF8.GetString(_privateKeyRsaProvider.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1));
                }

                #endregion

                #region 加密

                public string Encrypt(string text)
                {
                    if (_publicKeyRsaProvider == null)
                    {
                        throw new Exception("_publicKeyRsaProvider is null");
                    }
                    return Convert.ToBase64String(_publicKeyRsaProvider.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1));
                }

                #endregion

                #region 使用私钥创建RSA实例

                public RSA CreateRsaProviderFromPrivateKey(string privateKey)
                {
                    var privateKeyBits = Convert.FromBase64String(privateKey);

                    var rsa = RSA.Create();
                    var rsaParameters = new RSAParameters();

                    using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
                    {
                        byte bt = 0;
                        ushort twobytes = 0;
                        twobytes = binr.ReadUInt16();
                        if (twobytes == 0x8130)
                            binr.ReadByte();
                        else if (twobytes == 0x8230)
                            binr.ReadInt16();
                        else
                            throw new Exception("Unexpected value read binr.ReadUInt16()");

                        twobytes = binr.ReadUInt16();
                        if (twobytes != 0x0102)
                            throw new Exception("Unexpected version");

                        bt = binr.ReadByte();
                        if (bt != 0x00)
                            throw new Exception("Unexpected value read binr.ReadByte()");

                        rsaParameters.Modulus = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.Exponent = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.D = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.P = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.Q = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.DP = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.DQ = binr.ReadBytes(GetIntegerSize(binr));
                        rsaParameters.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
                    }

                    rsa.ImportParameters(rsaParameters);
                    return rsa;
                }

                #endregion

                #region 使用公钥创建RSA实例

                public RSA CreateRsaProviderFromPublicKey(string publicKeyString)
                {
                    // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
                    byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
                    byte[] seq = new byte[15];

                    var x509Key = Convert.FromBase64String(publicKeyString);

                    // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
                    using (MemoryStream mem = new MemoryStream(x509Key))
                    {
                        using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                        {
                            byte bt = 0;
                            ushort twobytes = 0;

                            twobytes = binr.ReadUInt16();
                            if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                                binr.ReadByte();    //advance 1 byte
                            else if (twobytes == 0x8230)
                                binr.ReadInt16();   //advance 2 bytes
                            else
                                return null;

                            seq = binr.ReadBytes(15);       //read the Sequence OID
                            if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                                return null;

                            twobytes = binr.ReadUInt16();
                            if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                                binr.ReadByte();    //advance 1 byte
                            else if (twobytes == 0x8203)
                                binr.ReadInt16();   //advance 2 bytes
                            else
                                return null;

                            bt = binr.ReadByte();
                            if (bt != 0x00)     //expect null byte next
                                return null;

                            twobytes = binr.ReadUInt16();
                            if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                                binr.ReadByte();    //advance 1 byte
                            else if (twobytes == 0x8230)
                                binr.ReadInt16();   //advance 2 bytes
                            else
                                return null;

                            twobytes = binr.ReadUInt16();
                            byte lowbyte = 0x00;
                            byte highbyte = 0x00;

                            if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                                lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                            else if (twobytes == 0x8202)
                            {
                                highbyte = binr.ReadByte(); //advance 2 bytes
                                lowbyte = binr.ReadByte();
                            }
                            else
                                return null;
                            byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                            int modsize = BitConverter.ToInt32(modint, 0);

                            int firstbyte = binr.PeekChar();
                            if (firstbyte == 0x00)
                            {   //if first byte (highest order) of modulus is zero, don't include it
                                binr.ReadByte();    //skip this null byte
                                modsize -= 1;   //reduce modulus buffer size by 1
                            }

                            byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                            if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                                return null;
                            int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                            byte[] exponent = binr.ReadBytes(expbytes);

                            // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                            var rsa = RSA.Create();
                            RSAParameters rsaKeyInfo = new RSAParameters
                            {
                                Modulus = modulus,
                                Exponent = exponent
                            };
                            rsa.ImportParameters(rsaKeyInfo);

                            return rsa;
                        }

                    }
                }

                #endregion

                #region 导入密钥算法

                private int GetIntegerSize(BinaryReader binr)
                {
                    byte bt = 0;
                    int count = 0;
                    bt = binr.ReadByte();
                    if (bt != 0x02)
                        return 0;
                    bt = binr.ReadByte();

                    if (bt == 0x81)
                        count = binr.ReadByte();
                    else
                    if (bt == 0x82)
                    {
                        var highbyte = binr.ReadByte();
                        var lowbyte = binr.ReadByte();
                        byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                        count = BitConverter.ToInt32(modint, 0);
                    }
                    else
                    {
                        count = bt;
                    }

                    while (binr.ReadByte() == 0x00)
                    {
                        count -= 1;
                    }
                    binr.BaseStream.Seek(-1, SeekOrigin.Current);
                    return count;
                }

                private bool CompareBytearrays(byte[] a, byte[] b)
                {
                    if (a.Length != b.Length)
                        return false;
                    int i = 0;
                    foreach (byte c in a)
                    {
                        if (c != b[i])
                            return false;
                        i++;
                    }
                    return true;
                }

                #endregion

            }

            /// <summary>
            /// RSA算法类型
            /// </summary>
            public enum RSAType
            {
                /// <summary>
                /// SHA1
                /// </summary>
                RSA = 0,
                /// <summary>
                /// RSA2 密钥长度至少为2048
                /// SHA256
                /// </summary>
                RSA2
            }
        }
        //处理cmd命令
        interface runApi<T, P>
        {
            string Run(T obj, P param);
        }
        public class cmdProcess : runApi<string, int>
        {

            //用cmd启动一个指定文件，获取输出，如果还没在指定的时间内执行完成就杀死它
            public string Run(string startFilePath, int timeout)
            {
                Process pro = new Process();
                FileInfo file = new FileInfo(startFilePath);
                pro.StartInfo.WorkingDirectory = file.Directory.FullName;
                pro.StartInfo.FileName = startFilePath;
                pro.StartInfo.CreateNoWindow = false;
                pro.StartInfo.UseShellExecute = false;
                pro.StartInfo.RedirectStandardInput = true;
                pro.StartInfo.RedirectStandardOutput = true;
                pro.StartInfo.RedirectStandardError = true;
                pro.Start();

                //pro.StandardInput.WriteLine("exit");

                pro.StandardInput.AutoFlush = true;


                if (pro.WaitForExit(timeout))
                {
                    string runOutMessage = pro.StandardOutput.ReadToEnd();
                    string errorMessage = pro.StandardError.ReadToEnd();
                    if (pro.ExitCode != 0)
                    {

                        if (errorMessage.Length > 0)
                        {
                            throw new Exception(errorMessage);
                        }
                        else
                        {
                            return runOutMessage;
                        }
                    }
                    else
                    {
                        return runOutMessage;
                    }
                }
                else
                {
                    if (pro.HasExited)
                    {
                        string runOutMessage = pro.StandardOutput.ReadToEnd();
                        string errorMessage = pro.StandardError.ReadToEnd();
                        return runOutMessage + "pid:" + pro.Id;
                    }
                    else
                    {
                        pro.Kill();
                        string runOutMessage = pro.StandardOutput.ReadLine();
                        //string errorMessage = pro.StandardError.ReadToEnd();
                        return runOutMessage + "pid:" + pro.Id;
                    }
                }
            }
            //用cmd执行一段命令并返回进程的pid
            public int Run(string cmdContent)
            {
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.Verb = "runas";
                p.Start();
                p.StandardInput.WriteLine(cmdContent);
                return p.Id;
            }
            //启动一个文件,没有执行完不杀死它，并返回pid
            public string RunNotKill(string startFilePath, int timeout)
            {
                Process pro = new Process();
                FileInfo file = new FileInfo(startFilePath);
                pro.StartInfo.WorkingDirectory = file.Directory.FullName;
                pro.StartInfo.FileName = startFilePath;
                pro.StartInfo.CreateNoWindow = false;
                pro.StartInfo.UseShellExecute = false;
                pro.StartInfo.RedirectStandardInput = true;
                pro.StartInfo.RedirectStandardOutput = true;
                pro.StartInfo.RedirectStandardError = true;
                pro.Start();

                //pro.StandardInput.WriteLine("exit");

                pro.StandardInput.AutoFlush = true;


                if (pro.WaitForExit(timeout))
                {
                    string runOutMessage = pro.StandardOutput.ReadToEnd();
                    string errorMessage = pro.StandardError.ReadToEnd();
                    if (pro.ExitCode != 0)
                    {

                        if (errorMessage.Length > 0)
                        {
                            throw new Exception(errorMessage);
                        }
                        else
                        {
                            return runOutMessage;
                        }
                    }
                    else
                    {
                        return runOutMessage;
                    }
                }
                else
                {
                    if (pro.HasExited)
                    {
                        string runOutMessage = pro.StandardOutput.ReadToEnd();
                        return runOutMessage + "pid:" + pro.Id;
                    }
                    else
                    {
                        return pro.Id.ToString();
                    }
                }
            }

            //杀死进程和子进程
            public static void KillProcessAndChildren(int pid)
            {
                Process tool = new Process();
                string exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "src\\cn\\internetware\\yancloud\\apihubservice\\resources\\killprocessAndChildren.exe");
                tool.StartInfo = new ProcessStartInfo(exePath, pid.ToString());
                tool.StartInfo.UseShellExecute = false;
                tool.StartInfo.RedirectStandardOutput = true;
                tool.Start();
            }
            public static void killProcessByPid(int pid)
            {
                Process p = Process.GetProcessById(pid);
                p.Kill();
            }
            public static int useStringToRunCmd(string commandToRun, bool needPid)
            {
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.CreateNoWindow = true;
                p.Start();
                p.StandardInput.WriteLine(commandToRun);
                return p.Id;
            }
            public static string useStringToRunCmd(string commandToRun)
            {
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.CreateNoWindow = true;
                p.Start();
                p.StandardInput.WriteLine(commandToRun);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                p.Close();
                return output;
            }
            public static int RunBat(string batPath)
            {
                Process pro = new Process();
                FileInfo file = new FileInfo(batPath);
                pro.StartInfo.WorkingDirectory = file.Directory.FullName;
                pro.StartInfo.FileName = batPath;
                pro.StartInfo.CreateNoWindow = true;
                pro.StartInfo.UseShellExecute = false;
                pro.StartInfo.RedirectStandardOutput = true;
                pro.Start();
                return pro.Id;
            }
            public static int RunAndRedirectOutput(string runPath, string outputFilePath)
            {
                var proc = new Process();
                proc.StartInfo.FileName = runPath;
                // set up output redirection
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.EnableRaisingEvents = true;
                proc.StartInfo.CreateNoWindow = true;
                // see below for output handler
                proc.ErrorDataReceived += proc_DataReceived;
                proc.OutputDataReceived += proc_DataReceived;

                proc.Start();

                proc.BeginErrorReadLine();
                proc.BeginOutputReadLine();

                return proc.Id;

                void proc_DataReceived(object sender, DataReceivedEventArgs e)
                {
                    // output will be in string e.Data
                }
            }
            public static bool PidExists(int pid)
            {
                //判断pid是否存在
                return Process.GetProcesses().Any(x => x.Id == pid);
            }
            public static void killProcessOfFile(string fileName)
            {
                Process tool = new Process();
                tool.StartInfo.FileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "src\\cn\\internetware\\yancloud\\apihubservice\\resources\\handle.exe");
                //tool.StartInfo.Arguments = fileName + " /accepteula";
                tool.StartInfo.Arguments = fileName;
                tool.StartInfo.UseShellExecute = false;
                tool.StartInfo.RedirectStandardOutput = true;
                tool.Start();
                //tool.WaitForExit();
                string outputTool = tool.StandardOutput.ReadToEnd();
                int processIdUsingThisFIle = -1;
                string matchPattern = @"(?<=\s+pid:\s+)\b(\d+)\b(?=\s+)";
                foreach (Match match in Regex.Matches(outputTool, matchPattern))
                {
                    try
                    {
                        if (processIdUsingThisFIle != int.Parse(match.Value))
                        {
                            processIdUsingThisFIle = int.Parse(match.Value);
                            Process.GetProcessById(int.Parse(match.Value)).Kill();
                        }
                    }
                    catch (System.InvalidOperationException e)
                    {
                        throw new UnauthorizedAccessException("have no right to kill the process " + processIdUsingThisFIle);
                    }
                }
            }
            public static void killProcessByProcessName(string processName)
            {
                Process[] p = Process.GetProcessesByName(processName);
                foreach (Process pi in p)
                {
                    pi.Kill();
                }
            }
            public static int findProcessOfFile(string fileName)
            {
                Process tool = new Process();
                tool.StartInfo.FileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "src\\cn\\internetware\\yancloud\\apihubservice\\resources\\handle.exe");
                //tool.StartInfo.Arguments = fileName + " /accepteula";
                tool.StartInfo.Arguments = fileName;
                tool.StartInfo.UseShellExecute = false;
                tool.StartInfo.RedirectStandardOutput = true;
                tool.Start();
                //tool.WaitForExit();
                string outputTool = tool.StandardOutput.ReadToEnd();
                int processIdUsingThisFIle = -1;
                string matchPattern = @"(?<=\s+pid:\s+)\b(\d+)\b(?=\s+)";
                foreach (Match match in Regex.Matches(outputTool, matchPattern))
                {
                    try
                    {
                        if (processIdUsingThisFIle != int.Parse(match.Value))
                        {
                            processIdUsingThisFIle = int.Parse(match.Value);
                            break;
                        }
                    }
                    catch (System.InvalidOperationException e)
                    {
                        throw new UnauthorizedAccessException("have no right to kill the process " + processIdUsingThisFIle);
                    }
                }
                return processIdUsingThisFIle;
            }
            public static int findPidofPort(int port)
            {
                int pidResult = -1;
                Process pro = new Process();
                // 设置命令行、参数  
                pro.StartInfo.FileName = "cmd.exe";
                pro.StartInfo.UseShellExecute = false;
                pro.StartInfo.RedirectStandardInput = true;
                pro.StartInfo.RedirectStandardOutput = true;
                pro.StartInfo.RedirectStandardError = true;
                pro.StartInfo.CreateNoWindow = true;
                // 启动CMD  
                pro.Start();
                // 运行端口检查命令  
                pro.StandardInput.WriteLine("netstat -ano|findstr \"" + port + "\"");
                pro.StandardInput.WriteLine("exit");
                // 获取结果  
                Regex reg = new Regex("//s+", RegexOptions.Compiled);
                string line = null;
                while ((line = pro.StandardOutput.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase))
                    {
                        pidResult = Int32.Parse(line.Substring(line.LastIndexOf(" ") + 1, line.Length - line.LastIndexOf(" ") - 1));
                        break;
                    }
                }
                pro.Close();
                return pidResult;
            }
        }
        //文件处理相关
        public class FilesUtil
        {

            //强制删除文件夹
            public static void forceDeleteDir(DirectoryInfo directoryInfo)
            {
                FileInfo[] fil = directoryInfo.GetFiles();
                foreach (FileInfo f in fil)
                {
                    forceDeleteFile(f);
                }
                DirectoryInfo[] dii = directoryInfo.GetDirectories();
                //获取子文件夹内的文件列表，递归删除  
                foreach (DirectoryInfo d in dii)
                {
                    forceDeleteDir(d);
                }
                //删除空文件夹                
                directoryInfo.Delete();
            }
            public static void forceDeleteDir(string dirPath)
            {
                forceDeleteDir(new DirectoryInfo(dirPath));
            }
            //强制删除文件
            public static void forceDeleteFile(FileInfo file)
            {
                SystemUtil.cmdProcess.killProcessOfFile(file.FullName);
                file.Delete();
            }
            public static void forceDeleteFile(string filePath)
            {
                forceDeleteFile(new FileInfo(filePath));
            }
            //解压指定文件夹下的所有压缩包，默认会替换
            public static string unzipFiles(string dirPath)
            {
                DirectoryInfo directorySelected = new DirectoryInfo(dirPath);
                foreach (FileInfo fileToDecompress in directorySelected.GetFiles("*.zip"))
                {
                    ZipFile.ExtractToDirectory(fileToDecompress.FullName, dirPath, true);
                    fileToDecompress.Delete();
                    return fileToDecompress.Name.Substring(0, fileToDecompress.Name.LastIndexOf("."));
                }
                return null;
            }
            public static void unzipFile(string zipPath)
            {

                ZipFile.ExtractToDirectory(zipPath, zipPath.Substring(0, zipPath.LastIndexOf("\\")), true);
                File.Delete(zipPath);
            }
            public static void unzipFile(string zipPath, string desDir)
            {

                ZipFile.ExtractToDirectory(zipPath, desDir, true);
                File.Delete(zipPath);
            }
            public static void copyFileToDir(string filePath, string desDir)
            {
                if (!Directory.Exists(desDir))
                {
                    Directory.CreateDirectory(desDir);
                }
                FileInfo f = new FileInfo(filePath);
                System.IO.File.Copy(filePath, desDir + "\\" + f.Name, true);
            }
            public static void copyFiles(string srcDir, string desDir)
            {
                if (!Directory.Exists(desDir))
                {
                    Directory.CreateDirectory(desDir);
                }
                if (System.IO.Directory.Exists(srcDir))
                {
                    string[] files = System.IO.Directory.GetFiles(srcDir);

                    // Copy the files and overwrite destination files if they already exist.
                    foreach (string s in files)
                    {
                        // Use static Path methods to extract only the file name from the path.
                        string fileName = System.IO.Path.GetFileName(s);
                        string destFile = System.IO.Path.Combine(desDir, fileName);
                        System.IO.File.Copy(s, destFile, true);
                    }
                    string[] fileDirs = System.IO.Directory.GetDirectories(srcDir);
                    foreach (string s in fileDirs)
                    {
                        string desSonDirName = s.Substring(s.LastIndexOf("\\") + 1);
                        copyFiles(Path.Combine(srcDir, desSonDirName), Path.Combine(desDir, desSonDirName));
                    }
                }
            }
            public static void deleteFiles(string[] filesPath)
            {
                foreach (string s in filesPath)
                {
                    if (System.IO.File.Exists(s))
                    {
                        System.IO.File.Delete(s);
                    }
                    if (System.IO.Directory.Exists(s))
                    {
                        System.IO.Directory.Delete(s);
                    }
                }
            }
            public static void deleteDirectory(string dirPath)
            {
                if (System.IO.Directory.Exists(dirPath))
                {
                    System.IO.Directory.Delete(dirPath, true);
                }
            }
            public static string findFilePathBySuffix(string folderEntry, string fileSuffix)
            {
                //根据文件名和文件夹位置寻找文件位置
                DirectoryInfo folder = new DirectoryInfo(folderEntry);
                if (!folder.Exists)
                {
                    return "";
                }
                foreach (FileInfo s in folder.GetFiles())
                {

                    if (s.Name.Substring(s.Name.LastIndexOf(".") + 1).Equals(fileSuffix))
                    {
                        return Path.Combine(folderEntry, s.Name);
                    }
                }
                foreach (DirectoryInfo filefolder in folder.GetDirectories())
                {
                    string findResult = findFilePathBySuffix(filefolder.FullName, fileSuffix);
                    if (!findResult.Equals(""))
                    {
                        return findResult;
                    }
                }
                return "";
            }
            public static string findFilePathByName(string folderEntry, string fileName)
            {
                //根据文件名和文件夹位置寻找文件位置
                DirectoryInfo folder = new DirectoryInfo(folderEntry);
                FileInfo fileInfo = new FileInfo(Path.Combine(folderEntry, fileName));
                if (fileInfo.Exists)
                {
                    return Path.Combine(folderEntry, fileName);
                }
                foreach (DirectoryInfo filefolder in folder.GetDirectories())
                {
                    string findResult = findFilePathByName(filefolder.FullName, fileName);
                    if (!findResult.Equals(""))
                    {
                        return findResult;
                    }
                }
                return "";
            }
            public static void addFirstLine(string content, string filePath)
            {
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                lines.Insert(0, content);
                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static void addEndLine(string content, string filePath)
            {
                if (!File.Exists(filePath))
                {
                    File.Create(filePath);
                }
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                if (lines.IndexOf(content) == -1)
                {
                    lines.Add(content);
                }
                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static void deleteFirstLine(string firstLineContent, string filePath)
            {
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                lines.Remove(firstLineContent);
                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static void exchangeOneLine(string LineContent, int lineIndex, string filePath)
            {
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                lines[lineIndex] = LineContent;
                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static void exchangeSomeLines(string[] LineContent, int[] linesIndex, string filePath)
            {
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                for (int i = 0; i < linesIndex.Length; i++)
                {
                    lines[linesIndex[i]] = LineContent[i];
                }
                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static string deleteEndLine(string filePath)
            {
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                string endLineContent = lines[lines.Count - 1];
                lines.RemoveAt(lines.Count - 1);
                File.WriteAllLines(filePath, lines.ToArray());
                return endLineContent;
            }
            public static void deleteOneLine(string content, string filePath)
            {
                List<string> lines = new List<string>(File.ReadAllLines(filePath));
                int index = lines.IndexOf(content);
                lines.RemoveAt(index);
                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static void updateOrCreateByFileContent(List<string> lines, string filePath)
            {
                if (!File.Exists(filePath))
                {
                    File.Create(filePath);
                }

                File.WriteAllLines(filePath, lines.ToArray());
            }
            public static void updateOrCreateByFileContent(string Content, string filePath)
            {
                File.WriteAllText(filePath, Content);
            }
        }
        //设置开机自动启动
        public class StartWhenOStartUtil
        {
            public static string getSystemStartupPath()
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            }
            public static string getUserStartupPath()
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            }
            public static void setStartWhenOsStart(string exeFilePath, string startServiceName)
            {
                #region 写一个脚本放到C盘启动目录下
                string exeRootEntry = exeFilePath.Substring(0, 1);
                int pos = exeFilePath.LastIndexOf("\\");
                int l = exeFilePath.Length;
                string fileName = exeFilePath.Substring(pos + 1, l - pos - 1);
                string fileDir = exeFilePath.Substring(0, pos);
                string[] lines = new string[3]; lines[0] = exeRootEntry + ":"; lines[1] = "cd " + fileDir; lines[2] = fileName;

                Trace.TraceInformation(lines.ToString());
                string apiStartBatsDirPath = Path.Combine(getUserStartupPath(), "apiStartBats");
                //string apiStartBatsDirPath = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\apiStartBats";
                if (!Directory.Exists(apiStartBatsDirPath))
                {
                    Directory.CreateDirectory(apiStartBatsDirPath);
                }
                System.IO.File.WriteAllLines(Path.Combine(apiStartBatsDirPath, startServiceName + ".bat"), lines);
                #endregion

                #region 创建启动vbs脚本
                string startVbsFilePath = Path.Combine(getSystemStartupPath(), "run" + startServiceName + ".vbs");
                //string startVbsFilePath = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\run.vbs";
                if (!File.Exists(startVbsFilePath))
                {
                    //                    File.Create(startVbsFilePath);
                    string[] vbsLines = { "Set ws = CreateObject(\"Wscript.Shell\")", "ws.run \"cmd /c " + apiStartBatsDirPath + "\\" + startServiceName + ".bat\",vbhide" };
                    System.IO.File.WriteAllLines(startVbsFilePath, vbsLines);
                }
                #endregion
            }
            //删除开机自动启动
            public static void deletStartWhenOsStart(string startServiceName)
            {
                string apiStartBatsDirPath = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\apiStartBats";
                string startVbsFilePath = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\run.vbs";
                FilesUtil.deleteFirstLine("ws.run \"cmd /c " + apiStartBatsDirPath + "\\" + startServiceName + ".bat\",vbhide", startVbsFilePath);
                System.IO.File.Delete(Path.Combine(apiStartBatsDirPath, startServiceName) + ".bat");
            }
        }
        //deal with ini file
        public class iniUtil
        {
            #region API函数声明

            [DllImport("kernel32")]//返回0表示失败，非0为成功
            private static extern long WritePrivateProfileString(string section, string key,
                string val, string filePath);

            [DllImport("kernel32")]//返回取得字符串缓冲区的长度
            private static extern long GetPrivateProfileString(string section, string key,
                string def, StringBuilder retVal, int size, string filePath);


            #endregion

            #region 读Ini文件

            public static string ReadIniData(string Section, string Key, string NoText, string iniFilePath)
            {
                if (File.Exists(iniFilePath))
                {
                    StringBuilder temp = new StringBuilder(1024);
                    GetPrivateProfileString(Section, Key, NoText, temp, 1024, iniFilePath);
                    return temp.ToString();
                }
                else
                {
                    return String.Empty;
                }
            }

            #endregion

            #region 写Ini文件

            public static bool WriteIniData(string Section, string Key, string Value, string iniFilePath)
            {
                if (File.Exists(iniFilePath))
                {
                    long OpStation = WritePrivateProfileString(Section, Key, Value, iniFilePath);
                    if (OpStation == 0)
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }

            #endregion
        }
        public class portUtil

        {
            public static string openPortFirewall(string ruleName, int port)
            {
                string str = "netsh advfirewall firewall add rule name=" + ruleName + " dir=in action=allow protocol=TCP localport=" + port.ToString() + "&exit";
                return SystemUtil.cmdProcess.useStringToRunCmd(str);
            }
            public static int findPortFromIni(string iniFilePath)
            {
                SystemUtil.FilesUtil.addFirstLine("[daas]", iniFilePath);
                int port = Int32.Parse(SystemUtil.iniUtil.ReadIniData("daas", "iw_port", "0", iniFilePath));
                SystemUtil.FilesUtil.deleteFirstLine("[daas]", iniFilePath);
                return port;
            }
            //从3722开始到60000
            public static int findUsablePort()
            {
                int BEGIN_PORT = 3722;
                int MAX_PORT = 60000;
                int pidofPrePort = cmdProcess.findPidofPort(BEGIN_PORT);
                int ans = 0;
                for (int i = BEGIN_PORT; i < MAX_PORT; i++)
                {
                    if (PortIsAvailable(i)) return i;
                    else
                    {
                        int nowPidOfport = cmdProcess.findPidofPort(i);
                        if (nowPidOfport == pidofPrePort)
                        {
                            ans++;
                            if (ans > 2)
                            {
                                cmdProcess.killProcessByPid(nowPidOfport);
                            }
                        }
                        else
                        {
                            pidofPrePort = nowPidOfport;
                            ans = 0;
                        }
                    }
                }
                return -1;
            }
            public static IList PortIsUsed()
            {
                //获取本地计算机的网络连接和通信统计数据的信息
                IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();

                //返回本地计算机上的所有Tcp监听程序
                IPEndPoint[] ipsTCP = ipGlobalProperties.GetActiveTcpListeners();

                //返回本地计算机上的所有UDP监听程序
                IPEndPoint[] ipsUDP = ipGlobalProperties.GetActiveUdpListeners();

                //返回本地计算机上的Internet协议版本4(IPV4 传输控制协议(TCP)连接的信息。
                TcpConnectionInformation[] tcpConnInfoArray = ipGlobalProperties.GetActiveTcpConnections();

                IList allPorts = new ArrayList();
                foreach (IPEndPoint ep in ipsTCP) allPorts.Add(ep.Port);
                foreach (IPEndPoint ep in ipsUDP) allPorts.Add(ep.Port);
                foreach (TcpConnectionInformation conn in tcpConnInfoArray) allPorts.Add(conn.LocalEndPoint.Port);

                return allPorts;
            }
            public static bool PortIsAvailable(int port)
            {
                bool isAvailable = true;

                IList portUsed = PortIsUsed();

                foreach (int p in portUsed)
                {
                    if (p == port)
                    {
                        isAvailable = false; break;
                    }
                }

                return isAvailable;
            }
        }
        public class ipUtil
        {
            public static string GetLocalIPAddress()
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
                throw new Exception("No network adapters with an IPv4 address in the system!");
            }
        }
        //not recommend to use this，you can better http tools here:https://github.com/restsharp/RestSharp
        public class httpUtil
        {
            public static string HttpGet(string Url)//发送GET请求
            {
                try
                {
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Url);
                    request.Method = "GET";
                    request.ContentType = "text/html;charset=UTF-8";

                    HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                    Stream myResponseStream = response.GetResponseStream();
                    StreamReader myStreamReader = new StreamReader(myResponseStream, Encoding.UTF8);
                    string retString = myStreamReader.ReadToEnd();
                    myStreamReader.Close();
                    myResponseStream.Close();
                    return retString;
                }
                catch (WebException e)
                {
                    throw new NetworkInformationException();
                }
            }
        }
        public class xmlUtil
        {
            /**
                * 
                * 根据xml文件路径和key取出对应的value
                * */
            public static string getValue(string xmlFilePath, string key)
            {
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(xmlFilePath);
                XmlNode xmlNode = xmldoc.SelectSingleNode(key).FirstChild;
                return xmlNode.InnerText;
            }

            //更新<add key="" value="">类型
            public static void UpdateAppSetting(string xmlFilePath, string xpath, string key, string value)
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(xmlFilePath);
                XmlNodeList list = doc.SelectNodes(xpath);
                for (int i = 0; i < list.Count; i++)
                {
                    if (list[i].Attributes[0].Value == key)
                    {
                        list[i].Attributes[1].Value = value;
                    }
                }
                StreamWriter swriter = new StreamWriter(xmlFilePath);
                XmlTextWriter xw = new XmlTextWriter(swriter);
                xw.Formatting = Formatting.Indented;
                doc.WriteTo(xw);
                xw.Close();
                swriter.Close();
            }
            //更新<add key="" value="">类型
            public static void UpdateOrAddAppSeting(string xmlFilePath, string xpath, string key, string value)
            {

            }
        }
        /*
            * 系统环境变量处理
            * */
        public class SysEnvironment
        {
            /// <summary>
            /// 获取系统环境变量
            /// </summary>
            /// <param name="name"></param>
            /// <returns></returns>
            public static string GetSysEnvironmentByName(string name)
            {
                string result = string.Empty;
                try
                {
                    result = OpenSysEnvironment().GetValue(name).ToString();//读取
                }
                catch (Exception)
                {

                    return string.Empty;
                }
                return result;

            }

            /// <summary>
            /// 打开系统环境变量注册表
            /// </summary>
            /// <returns>RegistryKey</returns>
            private static RegistryKey OpenSysEnvironment()
            {
                RegistryKey regLocalMachine = Registry.LocalMachine;
                RegistryKey regSYSTEM = regLocalMachine.OpenSubKey("SYSTEM", true);//打开HKEY_LOCAL_MACHINE下的SYSTEM 
                RegistryKey regControlSet001 = regSYSTEM.OpenSubKey("ControlSet001", true);//打开ControlSet001 
                RegistryKey regControl = regControlSet001.OpenSubKey("Control", true);//打开Control 
                RegistryKey regManager = regControl.OpenSubKey("Session Manager", true);//打开Control 

                RegistryKey regEnvironment = regManager.OpenSubKey("Environment", true);
                return regEnvironment;
            }

            /// <summary>
            /// 设置系统环境变量
            /// </summary>
            /// <param name="name">变量名</param>
            /// <param name="strValue">值</param>
            public static void SetSysEnvironment(string name, string strValue)
            {
                OpenSysEnvironment().SetValue(name, strValue);

            }

            /// <summary>
            /// 检测系统环境变量是否存在
            /// </summary>
            /// <param name="name"></param>
            /// <returns></returns>
            public static bool CheckSysEnvironmentExist(string name)
            {
                if (!string.IsNullOrEmpty(GetSysEnvironmentByName(name)))
                    return true;
                else
                    return false;
            }

            /// <summary>
            /// 添加到PATH环境变量（会检测路径是否存在，存在就不重复）
            /// </summary>
            /// <param name="strPath"></param>
            public static void SetPathAfter(string strHome)
            {
                string pathlist;
                pathlist = GetSysEnvironmentByName("PATH");
                //检测是否以;结尾
                if (pathlist.Substring(pathlist.Length - 1, 1) != ";")
                {
                    SetSysEnvironment("PATH", pathlist + ";");
                    pathlist = GetSysEnvironmentByName("PATH");
                }
                string[] list = pathlist.Split(';');
                bool isPathExist = false;

                foreach (string item in list)
                {
                    if (item == strHome)
                        isPathExist = true;
                }
                if (!isPathExist)
                {
                    SetSysEnvironment("PATH", pathlist + strHome + ";");
                }

            }

            public static void SetPathBefore(string strHome)
            {

                string pathlist;
                pathlist = GetSysEnvironmentByName("PATH");
                string[] list = pathlist.Split(';');
                bool isPathExist = false;

                foreach (string item in list)
                {
                    if (item == strHome)
                        isPathExist = true;
                }
                if (!isPathExist)
                {
                    SetSysEnvironment("PATH", strHome + ";" + pathlist);
                }

            }

            public static void SetPath(string strHome)
            {

                string pathlist;
                pathlist = GetSysEnvironmentByName("PATH");
                string[] list = pathlist.Split(';');
                bool isPathExist = false;

                foreach (string item in list)
                {
                    if (item == strHome)
                        isPathExist = true;
                }
                if (!isPathExist)
                {
                    SetSysEnvironment("PATH", pathlist + strHome + ";");

                }

            }

            [DllImport("Kernel32.DLL ", SetLastError = true)]
            public static extern bool SetEnvironmentVariable(string lpName, string lpValue);

        }

    }    
}
