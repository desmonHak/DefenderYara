
rule Trojan_Win64_Doina_ARAX_MTB{
	meta:
		description = "Trojan:Win64/Doina.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 83 f0 23 89 c1 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 83 45 fc 01 8b 45 fc 83 f8 0c 76 d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}