
rule Trojan_BAT_XWorm_MCK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 73 00 6f 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 } //1
		$a_01_1 = {65 36 66 32 36 39 34 32 2d 65 63 30 65 2d 34 37 36 37 2d 38 64 34 32 2d 66 39 30 30 36 37 33 36 39 35 37 30 } //1 e6f26942-ec0e-4767-8d42-f90067369570
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}