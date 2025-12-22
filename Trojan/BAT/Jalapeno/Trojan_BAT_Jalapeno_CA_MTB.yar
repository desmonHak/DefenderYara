
rule Trojan_BAT_Jalapeno_CA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 40 08 11 40 6d 61 0c 08 20 1e f8 0d bd 06 59 07 59 61 0c 08 06 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}