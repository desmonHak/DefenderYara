
rule Trojan_Win32_Phorpiex_SX_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 6b d2 0f 52 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 99 8b cf f7 f9 03 d6 } //20
		$a_03_1 = {53 8d 45 e8 50 ff 75 f8 8d 85 dc fc ff ff 50 ff 75 f0 ff 15 ?? ?? ?? ?? 8d 45 f8 50 68 } //10
		$a_80_2 = {78 6d 72 2e 65 78 65 } //xmr.exe  1
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1) >=31
 
}