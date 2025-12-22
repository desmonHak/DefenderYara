
rule TrojanDropper_Win64_Convagent_MK_MTB{
	meta:
		description = "TrojanDropper:Win64/Convagent.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 94 c3 9f 3e e3 ef 08 b6 f7 71 68 a1 32 3c ce ff c9 d0 e3 0f 02 d9 86 95 32 ba c2 ee 3b 26 } //25
	condition:
		((#a_01_0  & 1)*25) >=25
 
}