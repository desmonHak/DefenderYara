
rule Backdoor_Win64_CandleStone_A_dha{
	meta:
		description = "Backdoor:Win64/CandleStone.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 00 41 00 44 00 36 00 46 00 46 00 41 00 38 00 42 00 2d 00 35 00 33 00 37 00 39 00 2d 00 34 00 35 00 46 00 39 00 2d 00 38 00 36 00 39 00 35 00 2d 00 45 00 38 00 38 00 33 00 44 00 46 00 36 00 32 00 32 00 34 00 38 00 34 00 7d 00 } //1 {AD6FFA8B-5379-45F9-8695-E883DF622484}
	condition:
		((#a_01_0  & 1)*1) >=1
 
}