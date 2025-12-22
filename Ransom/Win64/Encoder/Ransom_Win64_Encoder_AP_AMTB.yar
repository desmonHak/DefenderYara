
rule Ransom_Win64_Encoder_AP_AMTB{
	meta:
		description = "Ransom:Win64/Encoder.AP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 57 4f 52 44 4c 45 57 41 52 45 2e } //Your system has been encrypted by WORDLEWARE.  1
		$a_80_1 = {57 4f 52 44 4c 45 57 41 52 45 20 77 69 6c 6c 20 62 65 67 69 6e 20 64 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 70 72 65 63 69 6f 75 73 20 64 61 74 61 21 } //WORDLEWARE will begin decrypting your precious data!  1
		$a_80_2 = {59 6f 75 20 64 6f 6e 27 74 20 6e 65 65 64 20 74 6f 20 70 61 79 20 6d 65 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 2e } //You don't need to pay me to get your files back.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}