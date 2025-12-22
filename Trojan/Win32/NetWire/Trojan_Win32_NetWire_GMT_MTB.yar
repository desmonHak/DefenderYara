
rule Trojan_Win32_NetWire_GMT_MTB{
	meta:
		description = "Trojan:Win32/NetWire.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 43 00 54 00 58 00 50 00 52 00 58 00 59 00 33 00 } //5 ACTXPRXY3
		$a_03_1 = {41 00 54 00 ?? 00 52 00 32 00 0c 00 52 00 48 00 49 00 54 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}