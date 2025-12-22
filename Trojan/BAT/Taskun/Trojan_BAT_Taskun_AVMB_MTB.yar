
rule Trojan_BAT_Taskun_AVMB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AVMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 08 06 7b ?? 00 00 04 09 6f ?? 00 00 0a 59 13 09 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 12 11 12 2c 05 38 ?? 00 00 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 13 11 13 2c 05 38 ?? 00 00 00 09 12 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}