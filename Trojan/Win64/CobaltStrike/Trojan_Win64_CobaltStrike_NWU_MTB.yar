
rule Trojan_Win64_CobaltStrike_NWU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 48 8b 45 ?? ba ?? ?? ?? ?? 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 00 31 c1 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 89 ca 88 10 48 83 45 ?? ?? 48 8b 45 ?? 48 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_NWU_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 54 63 68 6f 75 70 69 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 54 63 68 6f 75 70 69 2e 70 64 62 } //1 \Tchoupi\x64\Release\Tchoupi.pdb
		$a_01_1 = {41 64 64 20 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add ExclusionPath
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 65 66 65 6e 64 65 72 } //1 \Microsoft\Windows\Defender
		$a_01_3 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}