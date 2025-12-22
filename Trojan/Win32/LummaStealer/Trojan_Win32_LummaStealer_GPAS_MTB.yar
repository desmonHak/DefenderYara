
rule Trojan_Win32_LummaStealer_GPAS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GPAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 fe c2 33 c0 88 55 ?? 0f 1f 40 00 0f 1f 84 00 00 00 00 00 02 d0 32 ?? ?? ?? ?? 00 88 94 05 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}