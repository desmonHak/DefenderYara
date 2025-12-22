
rule Backdoor_BAT_Predatorpain_SK_MTB{
	meta:
		description = "Backdoor:BAT/Predatorpain.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 91 1f 1d 61 d2 9c 07 17 58 0b 07 06 8e 69 32 ec } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}