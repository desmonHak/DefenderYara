
rule Trojan_Win64_CobaltStrike_PCW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 6f 75 6c 64 20 67 65 74 20 50 61 79 6c 6f 61 64 20 66 72 6f 6d 20 72 65 73 6f 75 72 63 65 } //1 Could get Payload from resource
		$a_81_1 = {43 6f 75 6c 64 20 6e 6f 74 20 67 65 74 20 42 65 61 63 6f 6e 20 66 72 6f 6d 20 28 6c 6f 63 61 6c 29 20 72 65 73 6f 75 72 63 65 } //1 Could not get Beacon from (local) resource
		$a_81_2 = {42 45 41 43 4f 4e 5f 52 45 53 4f 55 52 43 45 } //1 BEACON_RESOURCE
		$a_81_3 = {52 61 6e 20 43 6f 62 61 6c 74 53 74 72 69 6b 65 } //1 Ran CobaltStrike
		$a_81_4 = {52 65 76 65 72 73 65 53 68 65 6c 6c 5f 25 73 5f 25 73 2e 65 78 65 } //1 ReverseShell_%s_%s.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}