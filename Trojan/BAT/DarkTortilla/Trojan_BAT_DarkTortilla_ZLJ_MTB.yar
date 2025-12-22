
rule Trojan_BAT_DarkTortilla_ZLJ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 17 da 0b 16 0c 2b 11 02 08 02 08 91 20 ec 00 00 00 61 b4 9c 08 1e d6 0c 08 07 31 eb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}