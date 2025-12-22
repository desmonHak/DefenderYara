
rule Trojan_Win64_TrojanProxy_MK_MTB{
	meta:
		description = "Trojan:Win64/TrojanProxy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8d 04 11 83 e0 ?? 48 8d 52 01 48 03 c3 0f b6 44 05 d0 30 42 ff } //15
		$a_03_1 = {48 8b c1 83 e0 ?? 48 03 c3 0f b6 44 05 d0 30 04 0a 48 ff c1 } //10
		$a_01_2 = {76 6d 63 68 65 63 6b 2e 64 6c 6c } //3 vmcheck.dll
		$a_01_3 = {56 42 6f 78 48 6f 6f 6b 2e 64 6c 6c } //2 VBoxHook.dll
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=30
 
}