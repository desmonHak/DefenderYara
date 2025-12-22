
rule Trojan_Win32_Zusy_KAI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_01_0 = {ac 0f b6 c0 aa 3b c3 75 } //8
		$a_01_1 = {40 89 10 b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 } //7
		$a_01_2 = {ac 88 07 47 84 c0 75 } //5
		$a_01_3 = {74 61 6b 65 6d 79 6f 6c 64 66 6f 6f 64 } //3 takemyoldfood
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*7+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3) >=23
 
}