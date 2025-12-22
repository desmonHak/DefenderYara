
rule Ransom_Win64_PhenolCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/PhenolCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 21 21 } //You are encrypted!!!  3
		$a_80_1 = {44 65 61 72 20 53 69 72 2f 4d 61 64 61 6d 2c 57 65 20 61 72 65 20 74 68 65 20 50 48 45 4e 4f 4c 20 54 65 41 6d } //Dear Sir/Madam,We are the PHENOL TeAm  1
		$a_80_2 = {32 30 32 35 20 52 61 6e 73 6f 6d 77 61 72 65 20 43 6f 2e } //2025 Ransomware Co.  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}