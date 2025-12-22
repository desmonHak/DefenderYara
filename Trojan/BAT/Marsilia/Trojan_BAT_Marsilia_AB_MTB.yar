
rule Trojan_BAT_Marsilia_AB_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 1a 00 20 2e 22 eb 4e 20 06 9d 10 15 61 20 01 00 00 00 63 20 f6 c4 88 f2 58 65 20 59 5b 79 df 61 61 fe 0e 1a 00 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}