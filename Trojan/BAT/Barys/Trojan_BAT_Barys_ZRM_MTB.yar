
rule Trojan_BAT_Barys_ZRM_MTB{
	meta:
		description = "Trojan:BAT/Barys.ZRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {10 00 00 01 06 07 03 6f ?? 00 00 0a 5d 91 07 1b 58 06 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 ?? 10 00 00 01 07 17 58 0b 07 02 8e 69 32 c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}