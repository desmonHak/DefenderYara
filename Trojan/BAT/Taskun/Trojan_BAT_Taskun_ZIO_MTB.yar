
rule Trojan_BAT_Taskun_ZIO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 17 62 11 13 61 11 04 1b 63 61 13 04 02 11 12 11 13 6f ?? 00 00 0a 13 14 04 03 6f ?? 00 00 0a 59 13 15 11 15 13 16 1a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}