
rule Trojan_Win64_Rhadamanthys_NQH_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NQH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 68 61 69 6e 69 6e 67 4d 6f 64 65 43 42 43 } //1 ChainingModeCBC
		$a_81_1 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_01_2 = {48 89 f8 80 30 70 4d 8d 6d 00 48 83 c0 01 48 39 f0 75 f0 } //1
		$a_01_3 = {80 30 7b 48 83 c0 01 4c 39 c0 75 f4 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}