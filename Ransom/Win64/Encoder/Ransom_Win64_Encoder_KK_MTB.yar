
rule Ransom_Win64_Encoder_KK_MTB{
	meta:
		description = "Ransom:Win64/Encoder.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 d0 99 f7 fe 48 63 d2 41 0f b6 04 14 42 30 04 13 49 83 c2 01 4c 39 d7 75 } //20
		$a_01_1 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //10 files have been encrypted
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}