
rule Trojan_Win32_GlassWorm_DA_MTB{
	meta:
		description = "Trojan:Win32/GlassWorm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 70 69 2e 6d 61 69 6e 6e 65 74 2d 62 65 74 61 2e 73 6f 6c 61 6e 61 2e 63 6f 6d } //10 api.mainnet-beta.solana.com
		$a_81_1 = {32 38 50 4b 6e 75 37 52 7a 69 7a 78 42 7a 46 50 6f 4c 70 36 39 48 4c 58 70 39 62 4a 4c 33 4a 46 74 54 32 73 35 51 7a 48 73 45 41 32 } //10 28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2
		$a_81_2 = {65 76 61 6c 28 61 74 6f 62 28 } //1 eval(atob(
		$a_81_3 = {2e 72 65 70 6c 61 63 65 28 } //1 .replace(
		$a_81_4 = {68 65 61 64 65 72 2e 67 65 74 28 61 74 6f 62 28 } //1 header.get(atob(
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=23
 
}