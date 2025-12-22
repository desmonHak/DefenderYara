
rule Ransom_Win64_Filecoder_SLCP_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SLCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 10 05 00 00 48 8d 50 08 48 8b 8d 30 05 00 00 48 8d 85 d0 02 00 00 48 89 54 24 20 49 89 c9 4c 8d 05 cb a8 34 00 ba 00 02 00 00 48 89 c1 e8 1c fb ff ff 48 8d 85 d0 00 00 00 48 89 c2 48 8d 05 b7 a8 34 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}