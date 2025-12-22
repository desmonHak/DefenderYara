
rule Trojan_BAT_ClipBanker_SPZC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SPZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 74 6f 20 70 72 6f 63 68 69 74 61 6c 20 74 6f 74 20 73 68 6c 75 68 61 } //2 kto prochital tot shluha
		$a_01_1 = {49 4c 6f 76 65 59 6f 75 72 4d 6f 74 68 65 72 } //1 ILoveYourMother
		$a_01_2 = {48 00 34 00 73 00 49 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 45 00 41 00 43 00 76 00 4c 00 4c 00 55 00 38 00 73 00 53 00 69 00 30 00 70 00 53 00 71 00 7a 00 55 00 53 00 36 00 31 00 49 00 42 00 51 00 41 00 66 00 50 00 45 00 45 00 66 00 44 00 67 00 41 00 41 00 41 00 41 00 3d 00 3d 00 } //1 H4sIAAAAAAAEACvLLU8sSi0pSqzUS61IBQAfPEEfDgAAAA==
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}