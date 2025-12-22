
rule Trojan_Win32_ClickFix_GGF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 29 00 2e 00 4e 00 65 00 78 00 74 00 28 00 29 00 2b 00 } //1 New-Object System.Random).Next()+
		$a_00_1 = {3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 ;powershell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}