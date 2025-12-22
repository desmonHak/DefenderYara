
rule Ransom_Win64_Filecoder_EABA_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.EABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_1 = {64 65 63 72 79 70 74 20 74 68 65 6d } //1 decrypt them
		$a_81_2 = {73 65 6e 64 20 24 31 30 30 20 74 6f 20 5b 61 74 74 61 63 6b 65 72 27 73 20 65 6d 61 69 6c 20 61 64 64 72 65 73 73 5d 2e } //1 send $100 to [attacker's email address].
		$a_81_3 = {64 2e 65 6e 63 72 79 70 74 65 64 } //1 d.encrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}