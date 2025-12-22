
rule Ransom_Win64_Filecoder_PAHR_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 57 38 41 b9 04 00 00 00 48 8b 4f 18 41 b8 00 30 00 00 ff } //2
		$a_01_1 = {41 0f b7 01 4d 8d 49 02 83 f8 61 8d 48 e0 0f 42 c8 45 6b db 21 44 03 d9 49 83 ea 01 75 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}