
rule Trojan_Win32_Amadey_SUPC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.SUPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 16 40 32 c5 88 02 48 ff c2 49 ff c8 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}