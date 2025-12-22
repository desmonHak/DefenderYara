
rule Trojan_Win32_LummaStealer_AT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 8b c3 25 ?? ?? ?? ?? 79 ?? 48 83 c8 ?? 40 33 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 ?? ?? ?? ?? 41 8b 45 ?? 30 0c 03 43 3b 5d ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}