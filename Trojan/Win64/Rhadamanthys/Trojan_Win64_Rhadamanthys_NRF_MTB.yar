
rule Trojan_Win64_Rhadamanthys_NRF_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 68 61 69 6e 69 6e 67 4d 6f 64 65 43 42 43 } //1 ChainingModeCBC
		$a_81_1 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_03_2 = {69 c0 6d 4e c6 41 31 d2 05 39 30 00 00 25 ff ff ff 7f 89 05 ?? ?? ?? ?? 48 83 c4 20 41 f7 f0 } //3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}