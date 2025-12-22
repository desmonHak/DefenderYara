
rule Trojan_Win32_LummaStealer_AHF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 fb 31 fb 21 d3 31 fb 89 f2 31 f2 21 c2 31 f2 29 d9 19 d5 89 cf } //30
		$a_03_1 = {31 ce 81 f6 ?? ?? ?? ?? 0f af 30 01 fe 4e a1 ?? ?? ?? ?? 89 34 b8 47 81 ff ?? ?? ?? ?? 75 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}