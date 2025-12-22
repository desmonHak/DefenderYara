
rule Trojan_Win32_RevShellz_ZA_MTB{
	meta:
		description = "Trojan:Win32/RevShellz.ZA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 74 00 2e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 54 00 43 00 50 00 43 00 6c 00 69 00 65 00 6e 00 74 00 28 00 24 00 } //1 Net.Sockets.TCPClient($
		$a_00_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 4a 00 6f 00 62 00 20 00 2d 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 } //1 Start-Job -ScriptBlock
		$a_00_2 = {53 00 65 00 74 00 2d 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 } //1 Set-Variable -Name
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}