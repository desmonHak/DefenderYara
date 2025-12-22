
rule Trojan_Win32_ClickFix_IIE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 42 00 6f 00 64 00 79 00 20 00 28 00 40 00 7b 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 24 00 65 00 6e 00 76 00 3a 00 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 3b 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 24 00 65 00 6e 00 76 00 3a 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00 } //1 -Body (@{username=$env:USERNAME;computername=$env:COMPUTERNAME
		$a_00_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}