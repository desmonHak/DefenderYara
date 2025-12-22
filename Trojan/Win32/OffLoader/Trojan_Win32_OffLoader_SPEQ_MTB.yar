
rule Trojan_Win32_OffLoader_SPEQ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 65 61 73 6f 6e 63 6f 61 6c 2e 78 79 7a 2f 67 79 77 65 73 2e 70 68 70 } //reasoncoal.xyz/gywes.php  4
		$a_80_1 = {67 6c 61 73 73 67 6f 76 65 72 6e 6d 65 6e 74 2e 69 6e 66 6f 2f 67 79 77 65 2e 70 68 70 } //glassgovernment.info/gywe.php  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}