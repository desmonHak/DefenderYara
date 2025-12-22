
rule Ransom_Win64_CyberVolk_PC_MTB{
	meta:
		description = "Ransom:Win64/CyberVolk.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {23 43 79 62 65 72 56 6f 6c 6b } //3 #CyberVolk
		$a_01_1 = {44 45 43 52 59 50 54 5f 49 4e 53 54 52 55 43 54 49 4f 4e 53 2e 74 78 74 } //1 DECRYPT_INSTRUCTIONS.txt
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 21 21 } //1 YOUR FILES HAVE BEEN ENCRYPTED!!!
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}