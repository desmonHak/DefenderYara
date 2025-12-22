
rule Trojan_Win32_ClickFix_GGN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 29 00 } //1 PowerShell]::Create()
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_2 = {2e 00 41 00 64 00 64 00 53 00 63 00 72 00 69 00 70 00 74 00 28 00 27 00 47 00 65 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 27 00 29 00 2e 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 29 00 } //1 .AddScript('Get-Process').Invoke()
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}