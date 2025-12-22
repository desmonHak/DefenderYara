
rule Trojan_Win32_OffLoader_SASP_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {6d 61 69 64 6a 65 6c 6c 79 66 69 73 68 2e 69 6e 66 6f 2f 74 72 75 2e 70 68 70 } //maidjellyfish.info/tru.php  4
		$a_80_1 = {74 68 69 6e 67 73 69 64 65 61 2e 69 6e 66 6f 2f 74 72 75 73 2e 70 68 70 } //thingsidea.info/trus.php  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}