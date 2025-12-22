
rule Trojan_BAT_PureLogs_PQ_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 16 11 05 8e 69 6f 10 00 00 0a 25 13 06 16 3d 0f 00 00 00 38 1b 00 00 00 38 df ff ff ff 38 00 00 00 00 11 01 11 05 16 11 06 6f 11 00 00 0a 38 c9 ff ff ff } //5
		$a_01_1 = {02 73 0b 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 19 00 00 0a 13 05 38 00 00 00 00 00 73 0c 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f 1a 00 00 0a 38 00 00 00 00 11 06 6f 13 00 00 0a 13 07 38 00 00 00 00 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}