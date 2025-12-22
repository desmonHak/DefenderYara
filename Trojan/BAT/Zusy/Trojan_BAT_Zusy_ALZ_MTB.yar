
rule Trojan_BAT_Zusy_ALZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0d 2b 12 07 09 08 09 6f ?? 00 00 0a 1f ?? 61 d2 9c 09 17 58 0d 09 08 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}