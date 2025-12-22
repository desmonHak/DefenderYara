
rule Backdoor_BAT_Remcos_GTD_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a de 0a 09 2c 06 09 6f ?? 00 00 0a dc 7e ?? ?? ?? ?? 06 8e 69 20 ?? ?? ?? ?? 1f 40 28 ?? 00 00 06 0b 06 16 07 06 8e 69 28 ?? 00 00 0a 7e ?? ?? ?? ?? 16 07 7e ?? ?? ?? ?? 16 12 02 28 ?? 00 00 06 15 28 ?? 00 00 06 26 20 ?? 03 00 00 28 ?? 00 00 0a 2b f4 } //10
		$a_01_1 = {34 00 35 00 2e 00 31 00 34 00 33 00 2e 00 31 00 36 00 37 00 2e 00 33 00 33 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}