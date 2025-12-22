
rule Trojan_Win32_GuLoader_RDO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4e 69 53 6f 75 72 63 65 20 49 6e 63 } //1 NiSource Inc
		$a_81_1 = {41 69 72 62 6f 72 6e 65 2c 20 49 6e 63 2e } //1 Airborne, Inc.
		$a_81_2 = {63 68 65 65 72 65 72 20 73 6b 6c 6d 73 6b 65 2e 65 78 65 } //1 cheerer sklmske.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}