
rule Trojan_Win32_OffLoader_SPWQ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 72 00 6f 00 77 00 6e 00 73 00 6d 00 6f 00 6b 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 62 00 75 00 74 00 2e 00 70 00 68 00 70 00 } //2 /crownsmoke.xyz/but.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_OffLoader_SPWQ_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.SPWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {62 6f 78 67 72 61 6e 64 66 61 74 68 65 72 2e 69 6e 66 6f 2f 70 6f 6c 69 2e 70 68 70 } //boxgrandfather.info/poli.php  4
		$a_80_1 = {63 68 69 63 6b 65 6e 73 6c 65 76 65 6c 2e 78 79 7a 2f 70 6f 6c 69 73 2e 70 68 70 } //chickenslevel.xyz/polis.php  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}