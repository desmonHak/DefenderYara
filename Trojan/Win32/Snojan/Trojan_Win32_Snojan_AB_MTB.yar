
rule Trojan_Win32_Snojan_AB_MTB{
	meta:
		description = "Trojan:Win32/Snojan.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 0c 89 f7 8b 84 b3 5c 01 00 00 83 f7 01 89 84 93 54 01 00 00 c7 84 b3 5c 01 00 00 ff ff ff ff 8b 44 b3 50 89 43 4c 8b 84 bb 5c 01 00 00 83 f8 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}