
rule Trojan_Win32_ClearEventLogViaPowerShell_A{
	meta:
		description = "Trojan:Win32/ClearEventLogViaPowerShell.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 65 00 61 00 72 00 2d 00 65 00 76 00 65 00 6e 00 74 00 6c 00 6f 00 67 00 20 00 2d 00 6c 00 6f 00 67 00 6e 00 61 00 6d 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 } //3 powershell.exe clear-eventlog -logname attackiq_
	condition:
		((#a_00_0  & 1)*3) >=3
 
}