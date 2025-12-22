
rule Trojan_Linux_SAgnt_AE_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.AE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 49 6e 66 6f 54 6f 53 65 6e 64 } //1 main.InfoToSend
		$a_01_1 = {6d 61 69 6e 2e 53 65 6e 64 49 6e 66 6f 54 6f 53 65 72 76 65 72 52 65 73 70 6f 6e 73 65 } //1 main.SendInfoToServerResponse
		$a_01_2 = {55 53 44 54 5f 47 65 74 41 64 64 72 65 73 73 42 61 6c 61 6e 63 65 52 65 73 70 6f 6e 73 65 } //1 USDT_GetAddressBalanceResponse
		$a_01_3 = {74 79 70 65 3a 2e 65 71 2e 6d 61 69 6e 2e 55 53 44 54 5f 47 65 74 41 64 64 72 65 73 73 42 61 6c 61 6e 63 65 52 65 73 70 6f 6e 73 65 54 6f 6b 65 6e } //1 type:.eq.main.USDT_GetAddressBalanceResponseToken
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}