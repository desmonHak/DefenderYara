
rule Ransom_Win64_Magniber_YBI_MTB{
	meta:
		description = "Ransom:Win64/Magniber.YBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a ae ae 06 00 00 90 13 32 e8 90 13 80 f5 ?? 90 13 88 2f 90 13 8a c5 90 13 48 ff c6 } //1
		$a_03_1 = {8a a6 62 ba 01 00 90 13 32 e0 90 13 80 f4 ?? 90 13 88 27 90 13 8a c4 90 13 48 ff c6 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}