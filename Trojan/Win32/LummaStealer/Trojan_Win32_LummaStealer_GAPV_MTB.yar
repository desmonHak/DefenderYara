
rule Trojan_Win32_LummaStealer_GAPV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GAPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af ca 01 f1 29 c8 89 c1 81 e1 ?? 00 00 00 81 f1 ?? 00 00 00 83 e0 ?? 29 c8 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 83 c0 01 89 04 24 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}