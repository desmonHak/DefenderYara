
rule Trojan_Win32_AuraStealer_GMX_MTB{
	meta:
		description = "Trojan:Win32/AuraStealer.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {93 93 74 6d 48 89 47 08 4d 89 37 49 89 77 ?? 4c 89 f8 0f 28 07 0f 57 00 0f 29 07 48 8d 5c 24 ?? 48 89 e9 48 89 ac 24 ?? ?? ?? ?? 48 89 da 41 ff d5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}