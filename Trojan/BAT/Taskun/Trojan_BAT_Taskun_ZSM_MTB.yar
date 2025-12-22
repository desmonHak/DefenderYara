
rule Trojan_BAT_Taskun_ZSM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b 11 46 1f 4f 5a 61 13 47 00 02 11 45 11 46 6f ?? 00 00 0a 13 48 04 03 6f ?? 00 00 0a 59 13 49 11 49 13 4a 11 4a 19 fe 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}