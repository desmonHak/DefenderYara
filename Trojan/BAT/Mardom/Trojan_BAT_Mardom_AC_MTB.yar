
rule Trojan_BAT_Mardom_AC_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e e8 02 00 04 20 b3 ca b4 ff 20 2e a2 20 24 59 20 46 55 c5 70 59 20 3f d3 ce 6a 61 7d fc 02 00 04 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}