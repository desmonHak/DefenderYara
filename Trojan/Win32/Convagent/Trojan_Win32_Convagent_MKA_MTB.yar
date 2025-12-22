
rule Trojan_Win32_Convagent_MKA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d a9 49 c1 ea 0f eb 02 8b 57 69 d2 0f 00 ff } //15
		$a_01_1 = {bc e8 c1 41 f7 e0 eb 01 04 b8 39 53 1c } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}