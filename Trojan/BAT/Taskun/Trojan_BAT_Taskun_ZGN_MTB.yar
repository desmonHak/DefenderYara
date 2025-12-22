
rule Trojan_BAT_Taskun_ZGN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0f 1f 61 5a 61 13 10 02 11 0e 11 0f 6f ?? 00 00 0a 13 11 04 03 6f ?? 00 00 0a 59 13 12 11 12 13 13 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}