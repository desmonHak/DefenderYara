
rule Trojan_Win32_Injuke_PGIN_MTB{
	meta:
		description = "Trojan:Win32/Injuke.PGIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 f3 30 d0 af f3 1c 1c 87 40 3f 1e 43 47 bc c2 1a ff 7c 17 99 08 72 35 35 f2 b3 17 23 70 25 25 13 30 03 00 07 00 00 00 01 00 00 11 02 28 0c 00 00 0a 2a 00 13 30 04 } //5
		$a_03_1 = {52 65 73 6f 6c 76 65 00 52 65 6d 6f 76 65 00 [0-0b] 2e 65 78 65 } //5
		$a_01_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //5 DebuggerHiddenAttribute
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}