
rule Trojan_BAT_LummaStealer_ZQM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ZQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0b 1a 5a 58 13 0c 11 09 08 5a 11 0b 58 13 0d 11 04 11 0c 18 58 91 13 0e 11 05 11 0d 20 ff 00 00 00 11 0e 59 1f 72 61 d2 9c 11 0b 17 58 13 0b 11 0b 08 32 c9 11 09 17 58 13 09 11 09 09 32 b2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}