
rule Trojan_Win64_Rhadamanthys_NQA_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6e c0 49 8d 41 10 66 0f 70 c0 00 66 0f fc c1 41 0f 11 01 } //1
		$a_01_1 = {48 89 c0 48 89 db 4c 89 c8 80 30 94 48 87 e4 48 83 c0 01 4c 39 c0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}