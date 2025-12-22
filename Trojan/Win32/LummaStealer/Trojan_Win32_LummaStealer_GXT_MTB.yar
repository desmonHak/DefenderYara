
rule Trojan_Win32_LummaStealer_GXT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d6 21 ce 31 ca 8d 14 72 35 ?? ?? ?? ?? 21 c8 01 c0 29 c2 89 54 24 ?? 8b 44 24 ?? 04 ?? 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 89 c1 83 e1 ?? d1 e1 83 f0 ?? 01 c8 89 04 24 } //10
		$a_03_1 = {89 d6 21 ce 31 ca 8d 14 72 83 f0 ?? 21 c8 01 c0 29 c2 89 54 24 ?? 8b 44 24 ?? 04 ?? 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 83 e8 ?? 89 04 24 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}