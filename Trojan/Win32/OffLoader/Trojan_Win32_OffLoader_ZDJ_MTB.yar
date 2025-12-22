
rule Trojan_Win32_OffLoader_ZDJ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 72 61 6e 67 65 66 6f 77 6c 2e 78 79 7a 2f 6f 63 74 6f 73 2e 70 68 70 3f } //://rangefowl.xyz/octos.php?  3
		$a_80_1 = {3a 2f 2f 69 6d 70 75 6c 73 65 69 63 65 2e 69 6e 66 6f 2f 6f 63 74 6f 2e 70 68 70 3f } //://impulseice.info/octo.php?  3
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}