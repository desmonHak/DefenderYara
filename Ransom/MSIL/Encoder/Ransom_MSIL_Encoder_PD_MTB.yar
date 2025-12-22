
rule Ransom_MSIL_Encoder_PD_MTB{
	meta:
		description = "Ransom:MSIL/Encoder.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 README.txt
		$a_01_1 = {2e 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 65 00 77 00 61 00 72 00 65 00 } //1 .ransomeware
		$a_01_2 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 41 00 52 00 45 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //2 YOUR FILES ARE ENCRYPTED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}