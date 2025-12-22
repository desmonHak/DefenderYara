
rule Ransom_MSIL_Encoder_PC_MTB{
	meta:
		description = "Ransom:MSIL/Encoder.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //1 Encrypted:
		$a_03_1 = {5c 52 61 78 78 6d 78 6d 78 6d 78 6d 5c [0-08] 5c [0-08] [0-08] 5c 52 61 78 78 6d 78 6d 78 6d 78 6d 2e 70 64 62 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}