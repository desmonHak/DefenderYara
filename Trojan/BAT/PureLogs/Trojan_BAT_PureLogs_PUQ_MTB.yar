
rule Trojan_BAT_PureLogs_PUQ_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.PUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 03 16 73 19 00 00 0a 13 05 38 00 00 00 00 00 73 0d 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06 6f ?? 00 00 0a 13 07 } //4
		$a_03_1 = {11 01 11 05 16 11 06 6f ?? 00 00 0a 38 } //2
		$a_01_2 = {20 00 10 00 00 8d 0f 00 00 01 13 05 38 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}