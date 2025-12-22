
rule Trojan_Win32_ClickFix_DHW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DHW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 69 00 6f 00 2e 00 70 00 61 00 74 00 68 00 5d 00 3a 00 3a 00 47 00 65 00 74 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 4e 00 61 00 6d 00 65 00 28 00 24 00 } //10 [io.path]::GetDirectoryName($
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=111
 
}