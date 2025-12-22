
rule Trojan_BAT_Taskun_ZXJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 01 00 0a 13 08 06 7b ?? 00 00 04 09 6f ?? 01 00 0a 59 13 09 09 12 08 28 ?? 01 00 0a 6f ?? 01 00 0a 11 09 17 59 25 13 09 16 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}