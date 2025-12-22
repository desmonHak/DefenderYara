
rule Trojan_Win32_OffLoader_POFB_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.POFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 61 66 74 65 72 74 68 6f 75 67 68 74 6c 69 71 75 69 64 2e 69 6e 66 6f 2f 6b 75 6b 69 2e 70 68 70 3f } //http://afterthoughtliquid.info/kuki.php?  4
		$a_80_1 = {68 74 74 70 3a 2f 2f 73 74 6f 6d 61 63 68 67 72 61 70 65 2e 78 79 7a 2f 6b 75 6b 69 73 2e 70 68 70 3f } //http://stomachgrape.xyz/kukis.php?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}