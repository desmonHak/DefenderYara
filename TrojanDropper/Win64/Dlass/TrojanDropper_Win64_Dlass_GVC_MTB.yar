
rule TrojanDropper_Win64_Dlass_GVC_MTB{
	meta:
		description = "TrojanDropper:Win64/Dlass.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 c9 7c 6e 00 ac ea 6a 00 00 a2 0a 00 6a db df 05 8a 7d 6a 00 00 d4 00 00 98 d8 59 76 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}