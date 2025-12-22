
rule Trojan_BAT_DarkTortilla_ZYJ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 0a 16 0b 2b 11 02 07 02 07 91 07 03 28 ?? 01 00 06 9c 07 17 d6 0b 07 06 31 eb 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}