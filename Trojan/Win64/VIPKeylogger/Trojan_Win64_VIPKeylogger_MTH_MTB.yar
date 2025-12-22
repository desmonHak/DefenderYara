
rule Trojan_Win64_VIPKeylogger_MTH_MTB{
	meta:
		description = "Trojan:Win64/VIPKeylogger.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b ca 41 b8 00 30 00 00 48 8b d1 33 c9 48 ff 25 bb 5f 06 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}