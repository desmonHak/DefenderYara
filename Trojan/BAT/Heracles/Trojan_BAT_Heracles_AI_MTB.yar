
rule Trojan_BAT_Heracles_AI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 12 18 28 3e 00 00 0a 9c 25 17 12 18 28 3f 00 00 0a 9c 25 18 12 18 28 40 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}