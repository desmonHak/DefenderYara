
rule Trojan_Win32_OffLoader_MKZ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 6e 65 65 64 70 6f 72 74 65 72 2e 69 6e 66 6f 2f 6a 69 6d 79 2e 70 68 70 3f } //://needporter.info/jimy.php?  4
		$a_80_1 = {3a 2f 2f 74 61 6c 6b 74 6f 65 2e 78 79 7a 2f 6a 69 6d 79 73 2e 70 68 70 3f } //://talktoe.xyz/jimys.php?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}