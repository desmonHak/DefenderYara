
rule Trojan_Win64_HuntingSnakes_PA_MTB{
	meta:
		description = "Trojan:Win64/HuntingSnakes.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 69 63 61 72 5f 66 75 64 2e 63 6f 6d } //1 eicar_fud.com
		$a_03_1 = {8b 45 fc 48 98 0f b6 84 05 ?? ?? ?? ?? 89 c2 8b 45 f4 31 d0 89 c2 8b 45 fc 48 98 88 94 05 ?? ?? ?? ?? 83 45 fc 01 8b 45 fc 3b 45 f8 7c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}