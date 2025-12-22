
rule Trojan_AndroidOS_Coper_J_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c7 89 34 24 e8 a6 f9 06 00 89 3c 24 e8 ce bc 06 00 } //1
		$a_01_1 = {53 83 ec 18 e8 00 00 00 00 5b 81 c3 41 58 07 00 0f 28 44 24 20 0f 11 04 24 e8 a0 f7 06 00 83 c4 18 5b c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}