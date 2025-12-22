
rule Trojan_BAT_DarkTortilla_AOJB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AOJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 03 1f 10 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 07 07 6f ?? ?? 00 0a 07 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0c 00 73 ?? ?? 00 0a 0d 00 09 08 17 ?? ?? 01 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 00 de 0e } //5
		$a_03_1 = {02 03 1b da 16 8d ?? 00 00 01 a2 02 03 1d da 02 03 1c da 9a 74 ?? 00 00 01 6f ?? ?? 00 0a 02 8e 69 20 00 01 00 00 5d 9a a2 02 8e 69 03 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}