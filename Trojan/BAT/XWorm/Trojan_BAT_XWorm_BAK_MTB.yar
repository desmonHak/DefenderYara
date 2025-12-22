
rule Trojan_BAT_XWorm_BAK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 07 02 11 07 91 08 11 07 08 8e 69 5d 91 61 d2 9c 11 07 17 58 13 07 11 07 02 8e 69 32 e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}