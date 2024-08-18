using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SharpStager // Note: actual namespace depends on the project name.
{
    public class Runner
    {
        public static void Run()
        {
            Main();
        }

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


        static byte[] syscallStruct = {
          0x4C, 0x8B, 0xD1,               // mov r10, rcx
          0xB8, 0xFF, 0x00, 0x00, 0x00,   // mov eax, FUNC
          0x0F, 0x05,                     // syscall
          0xC3};                            // ret

        public static void Main()
        {
            

            Console.WriteLine("[+] Looking for hooked functions!!!\n");
            string[] mySysCalls = { "NtOpenProcess", "NtAllocateVirtualMemory", "NtCreateSection", "NtMapViewOfSection", "NtCreateThread", "NtWriteVirtualMemory", "NtCreateThreadEx", "NtWaitForSingleObject" };
            CheckHooks(mySysCalls);
           
            Console.ReadKey();
        }

        public static IntPtr GetNTDLLBase()
        {
            Process hProc = Process.GetCurrentProcess();
            foreach (ProcessModule module in hProc.Modules)
            {
                if (module.ModuleName.Equals("ntdll.dll"))
                    return module.BaseAddress;
            }
            return IntPtr.Zero;
        }

        public static void CheckHooks(string[] syscallList)
        {
            IntPtr ntdllBase = GetNTDLLBase();
            IntPtr funcAddress = IntPtr.Zero;
            byte[] instructions;
            foreach (string funcName in syscallList)
            {
                
                funcAddress = GetProcAddress(ntdllBase, funcName);
                Console.WriteLine($"[+] {funcName} :");
                instructions = new byte[21];
                Marshal.Copy(funcAddress, instructions, 0, 21);
                if (isHooked(instructions[0]))
                {
                    Console.WriteLine("  -> Hooked!!" );
                    Console.WriteLine("  -> Address : 0x{0}", funcAddress.ToString("X"));
                    Console.WriteLine("  -> Instructions : {0}", ByteArrayToHexString(instructions));
                    Console.WriteLine("  -> Syscall Number Based on Neighbor {0}", ByteArrayToHexString(new byte[1] { returnBasedOnNeighbor(funcAddress) }));
                    
                }
                else
                {
                    Console.WriteLine("  -> NOT hooked!", funcName);
                    Console.WriteLine("  -> Address : 0x{0}", funcAddress.ToString("X"));
                    Console.WriteLine("  -> Instructions : 0x{0}", ByteArrayToHexString(instructions));
                    Console.WriteLine("  -> Syscall Number {0}", ByteArrayToHexString(new byte[1] { GetSyscallNumber(funcAddress) }));

                }
              

                Console.WriteLine("Resolve Syscall : 0x{0}", ResolveSyscallNumber(funcName, ntdllBase).ToString("X"));
                Console.WriteLine();
            }
        }

        public static bool isHooked(byte value)
        {
            byte mov = 0x4C;
            if (value != mov)
                return true;
            return false;
        }

        public static byte returnBasedOnNeighbor(IntPtr funcAddress)
        {
            byte counter = 1;
            byte[] instructions = new byte[21];
            while (true)
            {
                IntPtr nextFuncAddress = (IntPtr)((UInt64)funcAddress + (UInt64)32);
                Console.WriteLine(String.Format("Next Neighbor: {0} ", (nextFuncAddress).ToString("X")));
                instructions = new byte[21];
                Marshal.Copy(nextFuncAddress, instructions, 0, 21);
                Console.WriteLine(String.Format("Neighbor instructions: 0x{0}", BitConverter.ToString(instructions).Replace("-", ", 0x").ToLower()));
                if (!isHooked(instructions[0]))
                {
                    syscallStruct[4] = (byte)(instructions[4] - counter);
                    break;
                }
                else
                {
                    funcAddress = nextFuncAddress;
                    Console.WriteLine("Neighbor is also hooked ;(");
                }
                counter++;
            }
            byte neighborSyscall = instructions[4];
            byte syscallBasedOnNeighbor = (byte) (neighborSyscall - counter);
            return syscallBasedOnNeighbor;
        }



        // Helper methods to retrieve syscall numbers
        static byte GetSyscallNumber(IntPtr functionAddress)
        {
            return Marshal.ReadByte(functionAddress + 4);
        }

       

        public static string ByteArrayToHexString(byte[] byteArray)
        {
            // Use a StringBuilder for efficient string concatenation
            System.Text.StringBuilder hexString = new System.Text.StringBuilder(byteArray.Length * 4);

            foreach (byte b in byteArray)
            {
                hexString.AppendFormat("0x{0:x2}, ", b);
            }

            // Remove the trailing comma and space
            if (hexString.Length > 0)
            {
                hexString.Length -= 2;
            }

            return hexString.ToString();
        }

        public static byte ResolveSyscallNumber(string functionName, IntPtr ntdllBase)
        {
            IntPtr funcAddress = GetProcAddress(ntdllBase, functionName);
            Console.WriteLine($"[+] {functionName} :");
            byte[] instructions = new byte[21];
            Marshal.Copy(funcAddress, instructions, 0, 21);
            if (isHooked(instructions[0]))
            {
               return returnBasedOnNeighbor(funcAddress);
            }
            else
            {
                return GetSyscallNumber(funcAddress);
            }
        }

    }
}