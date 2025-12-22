
rule Trojan_BAT_Mardom_ZOM_MTB{
	meta:
		description = "Trojan:BAT/Mardom.ZOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 28 ?? 00 00 06 13 09 11 09 72 a1 02 00 70 08 28 ?? 00 00 06 11 09 72 a9 02 00 70 09 28 ?? 00 00 06 14 13 0a 16 13 0b 1f 0a 11 0b 5b 26 de 0c 26 11 09 28 ?? 00 00 06 13 0a de 00 11 0a 11 04 28 ?? 00 00 06 13 04 11 04 28 ?? 00 00 06 13 0c 11 0c 28 ?? 00 00 06 13 0d 11 0d 02 28 ?? 00 00 06 de 11 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}