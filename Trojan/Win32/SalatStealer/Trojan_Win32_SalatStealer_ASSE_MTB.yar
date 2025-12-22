
rule Trojan_Win32_SalatStealer_ASSE_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.ASSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 2c 8b 44 24 28 89 44 24 30 8d 05 f9 5f 98 00 89 04 24 c7 44 24 04 ?? ?? ?? ?? 8d 44 24 2c 89 44 24 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}