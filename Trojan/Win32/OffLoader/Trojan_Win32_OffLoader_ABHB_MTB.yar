
rule Trojan_Win32_OffLoader_ABHB_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ABHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 74 72 61 79 6d 69 74 74 65 6e 2e 69 6e 66 6f 2f 6e 75 6c 6f 2e 70 68 70 3f } //://traymitten.info/nulo.php?  4
		$a_80_1 = {3a 2f 2f 70 6f 73 69 74 69 6f 6e 70 61 69 6c 2e 78 79 7a 2f 6e 75 6c 6f 73 2e 70 68 70 3f } //://positionpail.xyz/nulos.php?  4
		$a_80_2 = {3a 2f 2f 77 69 72 65 73 77 69 6d 2e 69 6e 66 6f 2f 74 75 79 6f 2e 70 68 70 3f } //://wireswim.info/tuyo.php?  4
		$a_80_3 = {3a 2f 2f 70 6c 61 6e 74 73 77 61 76 65 73 2e 78 79 7a 2f 74 75 79 6f 73 2e 70 68 70 3f } //://plantswaves.xyz/tuyos.php?  4
		$a_80_4 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_5 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=10
 
}