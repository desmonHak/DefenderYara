
rule Trojan_Win32_SalatStealer_ASE_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 3c 3a 31 ef 8b 6c 24 48 97 88 04 2b 97 8d 45 01 89 f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}