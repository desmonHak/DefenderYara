
rule Trojan_Win32_OffLoader_POFA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.POFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 71 75 65 73 74 69 6f 6e 74 65 6e 64 65 6e 63 79 2e 78 79 7a 2f 61 6c 6c 69 73 2e 70 68 70 3f } //http://questiontendency.xyz/allis.php?  4
		$a_80_1 = {68 74 74 70 3a 2f 2f 74 65 6d 70 65 72 63 72 65 61 6d 2e 69 6e 66 6f 2f 61 6c 6c 69 2e 70 68 70 3f } //http://tempercream.info/alli.php?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}