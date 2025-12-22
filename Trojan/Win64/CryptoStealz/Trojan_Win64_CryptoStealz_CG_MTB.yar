
rule Trojan_Win64_CryptoStealz_CG_MTB{
	meta:
		description = "Trojan:Win64/CryptoStealz.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 0a 00 00 "
		
	strings :
		$a_01_0 = {61 67 65 6e 74 5f 69 64 48 } //5 agent_idH
		$a_01_1 = {68 6f 73 74 6e 61 6d 65 48 } //5 hostnameH
		$a_01_2 = {69 70 5f 61 64 64 72 65 48 } //5 ip_addreH
		$a_01_3 = {6c 6f 63 61 74 69 6f 6e 48 } //5 locationH
		$a_01_4 = {63 70 75 5f 6d 6f 64 65 48 } //5 cpu_modeH
		$a_01_5 = {70 75 5f 6d 6f 64 65 48 } //5 pu_modeH
		$a_01_6 = {61 6e 74 69 76 69 72 75 48 } //5 antiviruH
		$a_01_7 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 CurrentVersion\Run
		$a_01_8 = {56 42 6f 78 47 75 65 73 74 2e 73 79 73 } //5 VBoxGuest.sys
		$a_01_9 = {73 61 6e 64 62 6f 78 5f 65 76 61 73 69 6f 6e 2e 72 73 } //5 sandbox_evasion.rs
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=40
 
}