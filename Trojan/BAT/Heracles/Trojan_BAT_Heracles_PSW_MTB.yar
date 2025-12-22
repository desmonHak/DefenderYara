
rule Trojan_BAT_Heracles_PSW_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 16 06 16 95 07 16 95 58 20 3d 86 51 13 58 9e 06 17 06 17 95 07 17 95 58 20 af 16 84 8e 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}