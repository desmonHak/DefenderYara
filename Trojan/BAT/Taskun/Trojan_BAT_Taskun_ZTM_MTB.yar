
rule Trojan_BAT_Taskun_ZTM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 11 07 1b 63 61 61 13 07 16 13 18 38 ad 00 00 00 02 11 17 11 18 6f ?? 00 00 0a 13 19 04 03 6f ?? 00 00 0a 59 13 1a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}