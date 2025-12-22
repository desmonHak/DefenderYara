
rule Trojan_BAT_Taskun_ZHM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 11 0e 1a 63 61 61 13 0e 16 13 2c 38 ?? 00 00 00 02 11 2b 11 2c 6f ?? 00 00 0a 13 2d 04 03 6f ?? 00 00 0a 59 13 2e 11 2e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}