
rule Ransom_MSIL_Filecoder_J_AMTB{
	meta:
		description = "Ransom:MSIL/Filecoder.J!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 8d 13 00 00 01 13 06 2b 0c 11 05 11 06 16 11 07 6f ?? ?? ?? 0a 09 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 25 13 07 16 30 e1 } //5
		$a_80_1 = {2e 6d 65 6f 77 65 64 } //.meowed  1
		$a_80_2 = {2e 6d 6f 75 7a 64 } //.mouzd  1
		$a_80_3 = {2e 6c 6f 63 6b 65 64 } //.locked  1
		$a_80_4 = {2e 68 61 72 6d 73 74 72 65 65 74 } //.harmstreet  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}