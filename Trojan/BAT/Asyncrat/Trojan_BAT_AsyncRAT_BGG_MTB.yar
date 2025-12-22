
rule Trojan_BAT_AsyncRAT_BGG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 17 73 10 00 00 0a 13 04 11 04 02 16 02 8e 69 ?? ?? ?? ?? ?? de 0c 11 04 2c 07 11 04 ?? ?? ?? ?? ?? dc 09 ?? ?? ?? ?? ?? 13 05 de 1e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}