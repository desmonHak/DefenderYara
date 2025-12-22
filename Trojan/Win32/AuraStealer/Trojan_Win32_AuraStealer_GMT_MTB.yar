
rule Trojan_Win32_AuraStealer_GMT_MTB{
	meta:
		description = "Trojan:Win32/AuraStealer.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 28 00 0f 57 02 31 c9 80 7e ?? 01 0f 29 00 89 46 ?? 0f 94 c1 } //5
		$a_03_1 = {0f 28 03 0f 57 00 0f 29 03 89 5e ?? 8b 46 ?? 80 38 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}