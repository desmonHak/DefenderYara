
rule Trojan_Win32_PonyStealer_AHC_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 00 30 38 46 00 13 00 10 49 ?? 48 54 54 50 48 } //30
		$a_03_1 = {8f 46 00 07 54 49 64 58 35 ?? ?? ?? ?? 46 00 07 07 54 49 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}