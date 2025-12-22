
rule Trojan_Win64_DiscordStealer_ARA_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 65 6e 74 20 50 43 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 74 6f 20 44 69 73 63 6f 72 64 } //2 Successfully sent PC information to Discord
		$a_01_1 = {43 6f 6d 70 75 74 65 72 20 4e 61 6d 65 } //2 Computer Name
		$a_01_2 = {55 73 65 72 6e 61 6d 65 } //2 Username
		$a_01_3 = {4f 53 20 56 65 72 73 69 6f 6e } //2 OS Version
		$a_01_4 = {43 50 55 20 49 6e 66 6f } //2 CPU Info
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}