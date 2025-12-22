
rule Trojan_BAT_RedlineStealer_ZEK_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.ZEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 32 05 dd 48 01 00 00 02 08 09 6f ?? 00 00 0a 13 08 03 07 6f ?? 00 00 0a 59 13 09 11 05 07 6f ?? 00 00 0a 61 19 5f 13 0b 11 0b 2c 0c 11 0b 17 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}