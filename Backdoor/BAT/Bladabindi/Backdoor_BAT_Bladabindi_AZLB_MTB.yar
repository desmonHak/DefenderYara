
rule Backdoor_BAT_Bladabindi_AZLB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AZLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e7 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 06 28 ?? 00 00 06 28 ?? 00 00 06 16 9a 17 8d ?? 00 00 01 0d 09 16 7e ?? 00 00 04 d0 ?? 00 00 02 28 ?? 00 00 06 a2 09 28 ?? 00 00 06 26 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}