
rule Trojan_Win64_Vidar_ATR_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 32 44 30 c3 88 1c 31 8b 3d ?? ?? ?? ?? 8d 6f ?? 0f af ef } //5
		$a_03_1 = {44 0f af f8 41 f6 c7 ?? b8 ?? ?? ?? ?? 41 0f 44 c6 } //3
		$a_03_2 = {48 8b 45 e8 48 8b 45 f0 8b 05 ?? ?? ?? ?? 8d 50 ?? 0f af d0 f6 c2 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}