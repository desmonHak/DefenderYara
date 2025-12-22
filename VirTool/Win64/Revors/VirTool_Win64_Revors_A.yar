
rule VirTool_Win64_Revors_A{
	meta:
		description = "VirTool:Win64/Revors.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 69 73 74 65 72 42 65 61 63 6f 6e } //1 registerBeacon
		$a_01_1 = {68 74 74 70 70 72 6f 78 79 70 61 73 73 77 6f 72 64 } //1 httpproxypassword
		$a_01_2 = {62 65 61 63 6f 6e 54 61 73 6b 52 65 74 72 69 65 76 65 } //1 beaconTaskRetrieve
		$a_01_3 = {68 6f 73 74 45 6e 64 70 6f 69 6e 74 } //1 hostEndpoint
		$a_01_4 = {61 75 74 6f 72 6f 75 74 65 4d 65 73 73 61 67 65 } //1 autorouteMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}