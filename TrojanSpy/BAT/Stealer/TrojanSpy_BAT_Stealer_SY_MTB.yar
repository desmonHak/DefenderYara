
rule TrojanSpy_BAT_Stealer_SY_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 69 02 00 70 28 5d 01 00 0a 26 02 28 12 00 00 0a 0a 28 33 00 00 0a 06 16 06 8e 69 6f cf 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}