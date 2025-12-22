
rule Trojan_Win64_KatzStealer_GMX_MTB{
	meta:
		description = "Trojan:Win64/KatzStealer.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 91 41 ff d4 49 91 4d 85 c9 ?? ?? 48 8b 05 ?? ?? ?? ?? 48 89 d9 45 31 c0 31 d2 48 89 74 24 ?? 48 89 44 24 ?? 48 83 64 24 ?? 00 83 64 24 ?? 00 ff d0 } //5
		$a_03_1 = {48 83 64 24 ?? 00 48 89 f2 48 89 d9 4c 8d 48 ?? 48 8b 05 ?? ?? ?? ?? 4c 8b 84 24 ?? ?? ?? ?? 48 89 44 24 ?? ff d0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}