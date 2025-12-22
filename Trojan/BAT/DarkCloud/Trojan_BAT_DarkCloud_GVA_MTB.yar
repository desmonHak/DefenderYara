
rule Trojan_BAT_DarkCloud_GVA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 c4 ff ff ff 26 20 00 00 00 00 38 b9 ff ff ff 7e 02 00 00 04 fe 06 0c 00 00 06 73 01 00 00 0a 25 80 05 00 00 04 28 04 00 00 06 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}