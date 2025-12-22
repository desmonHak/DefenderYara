
rule Trojan_BAT_Taskun_ZGK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 10 2c 05 38 ?? 01 00 00 02 08 09 6f ?? 00 00 0a 13 09 03 07 6f ?? 00 00 0a 59 13 0a 11 05 07 6f ?? 00 00 0a 61 19 5f 13 12 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}