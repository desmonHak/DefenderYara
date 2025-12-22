
rule Trojan_BAT_CelestialRat_AUGB_MTB{
	meta:
		description = "Trojan:BAT/CelestialRat.AUGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 02 09 7e ?? 00 00 04 8e 69 58 91 07 09 07 8e 69 5d 91 61 d2 9c } //5
		$a_01_1 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //1 Confuser.Core
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}