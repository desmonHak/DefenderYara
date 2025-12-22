
rule Backdoor_BAT_Bladabindi_AHMB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AHMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 6f ?? 00 00 0a 00 09 04 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 13 05 09 6f ?? 00 00 0a 00 11 05 0a 2b 00 06 2a } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}