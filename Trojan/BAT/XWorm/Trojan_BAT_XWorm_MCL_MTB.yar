
rule Trojan_BAT_XWorm_MCL_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 37 35 62 30 37 62 62 2d 31 63 63 30 2d 34 39 36 33 2d 62 38 36 66 2d 36 33 61 32 38 64 34 62 63 66 36 37 } //1 475b07bb-1cc0-4963-b86f-63a28d4bcf67
		$a_01_1 = {6f 70 64 6d 6d 69 6d 63 6f 65 2e 65 78 65 } //1 opdmmimcoe.exe
		$a_01_2 = {37 7a 53 2e 73 66 78 } //1 7zS.sfx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}