
rule Trojan_Win32_LummaStealer_GAPI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GAPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c1 81 f1 ?? ?? ?? ?? 89 4c 24 04 8b 44 24 04 04 ?? 8b 4c 24 0c 8b 14 24 88 04 11 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}