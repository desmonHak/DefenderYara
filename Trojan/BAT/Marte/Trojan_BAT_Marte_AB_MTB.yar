
rule Trojan_BAT_Marte_AB_MTB{
	meta:
		description = "Trojan:BAT/Marte.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0b 06 07 16 1a 6f 1d 00 00 0a 26 07 16 28 1c 00 00 0a 0c 06 16 73 cd 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}