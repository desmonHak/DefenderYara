
rule Trojan_Win64_CobaltStrike_GVC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f8 8d 4a 04 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 54 24 68 48 8b d8 ff 15 ?? ?? ?? ?? 85 c0 [0-0a] 48 8b cb 39 7c 24 74 ?? ?? 48 8d 54 24 68 ff 15 ?? ?? ?? ?? 85 c0 75 e8 } //2
		$a_01_1 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Windows\CurrentVersion\Run
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}