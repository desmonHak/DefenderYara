
rule TrojanDropper_BAT_QuasarRAT_P_AMTB{
	meta:
		description = "TrojanDropper:BAT/QuasarRAT.P!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 8f 0a 00 00 01 25 71 0a 00 00 01 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 d2 81 0a 00 00 01 07 17 58 0b 07 06 8e 69 32 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}