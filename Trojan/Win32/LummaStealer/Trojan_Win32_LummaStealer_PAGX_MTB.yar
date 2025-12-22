
rule Trojan_Win32_LummaStealer_PAGX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PAGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 8b 04 77 66 83 e8 ?? 66 83 f0 ?? 66 89 04 77 46 57 e8 ?? ?? ?? ?? 59 3b f0 72 } //2
		$a_00_1 = {53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 65 00 72 00 } //1 Screenshoter
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}