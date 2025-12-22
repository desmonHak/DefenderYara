
rule Trojan_BAT_AsyncRAT_BGH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 73 11 00 00 0a 0c 08 02 16 02 8e 69 ?? ?? ?? ?? ?? 08 6f 13 00 00 0a de 0a 08 2c 06 08 ?? ?? ?? ?? ?? dc 07 ?? ?? ?? ?? ?? 0d de 14 07 2c 06 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}