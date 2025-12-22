
rule Trojan_BAT_PhantomStealer_APH_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.APH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 7d ?? 00 00 04 00 06 7b ?? 00 00 04 14 fe 01 13 0c 11 0c 2c 05 38 ?? 00 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 0b 06 06 7b ?? 00 00 04 6f ?? 00 00 0a 7d ?? 00 00 04 07 06 7b ?? 00 00 04 5a 19 5a 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}