
rule Trojan_Win32_Radthief_ADR_MTB{
	meta:
		description = "Trojan:Win32/Radthief.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 74 24 20 03 f7 47 0f b6 0c 33 69 c9 b9 00 00 00 32 0c 33 88 0e 3b fd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}