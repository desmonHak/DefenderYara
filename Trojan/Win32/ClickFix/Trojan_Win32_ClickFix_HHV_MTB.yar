
rule Trojan_Win32_ClickFix_HHV_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {28 00 5b 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 28 00 69 00 77 00 72 00 } //1 ([ScriptBlock]::Create((iwr
		$a_00_1 = {20 00 2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 29 00 } //1  -Method POST).Content)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ClickFix_HHV_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.HHV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 74 00 2e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 54 00 63 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.Sockets.TcpClient
		$a_00_1 = {2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 52 00 65 00 61 00 64 00 65 00 72 00 28 00 24 00 } //1 .StreamReader($
		$a_00_2 = {57 00 72 00 69 00 74 00 65 00 28 00 24 00 } //1 Write($
		$a_00_3 = {70 00 77 00 64 00 } //1 pwd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}