
rule Trojan_BAT_Radthief_NPA_MTB{
	meta:
		description = "Trojan:BAT/Radthief.NPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 02 03 60 02 66 03 66 60 5f 0a 2b 00 06 2a } //2
		$a_03_1 = {00 1f 09 0b 04 03 07 5d 9a ?? ?? 00 00 0a 02 ?? ?? 01 00 06 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}