
rule Trojan_BAT_Taskun_ZDM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 11 0b 1a 63 61 61 13 0b 16 13 17 38 ?? 00 00 00 02 11 16 11 17 6f ?? 00 00 0a 13 18 04 03 6f ?? 00 00 0a 59 13 19 11 19 19 31 03 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}