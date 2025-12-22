
rule Trojan_BAT_Zilla_ZUJ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 07 07 8e 69 17 59 91 1f 70 61 0d 07 8e 69 17 58 8d ?? 00 00 01 13 04 16 13 05 16 13 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}