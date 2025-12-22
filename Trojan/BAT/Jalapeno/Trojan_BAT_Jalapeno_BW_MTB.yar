
rule Trojan_BAT_Jalapeno_BW_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 11 25 9c 25 17 11 26 9c 25 18 11 27 9c 13 32 11 0b 20 e8 03 00 00 5d 20 e7 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}