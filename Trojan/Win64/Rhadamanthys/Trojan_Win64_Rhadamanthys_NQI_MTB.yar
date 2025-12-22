
rule Trojan_Win64_Rhadamanthys_NQI_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 68 61 69 6e 69 6e 67 4d 6f 64 65 43 42 43 } //1 ChainingModeCBC
		$a_81_1 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_01_2 = {f3 0f 6f 00 48 83 c0 10 66 0f ef c1 0f 11 40 f0 } //1
		$a_01_3 = {48 89 c2 66 0f 70 c0 00 66 0f ef c8 66 0f ef c2 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}