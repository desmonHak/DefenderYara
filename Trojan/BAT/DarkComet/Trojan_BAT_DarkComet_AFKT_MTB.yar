
rule Trojan_BAT_DarkComet_AFKT_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AFKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 02 11 05 91 11 04 61 08 06 91 61 b4 9c 1f 0c 13 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}