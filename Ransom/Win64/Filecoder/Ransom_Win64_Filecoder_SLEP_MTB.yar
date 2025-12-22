
rule Ransom_Win64_Filecoder_SLEP_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SLEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {e9 da 02 00 00 48 8d 85 90 12 00 00 4c 8d 05 9a 98 46 00 48 8b 95 f0 14 00 00 48 89 c1 e8 0c 0e 43 00 48 8d 95 90 12 00 00 48 8d 85 c0 10 00 00 41 b8 04 00 00 00 48 89 c1 } //2
		$a_01_1 = {72 61 6e 73 6f 6d 2e 74 78 74 } //1 ransom.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}