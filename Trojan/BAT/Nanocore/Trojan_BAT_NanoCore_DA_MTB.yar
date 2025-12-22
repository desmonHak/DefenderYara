
rule Trojan_BAT_NanoCore_DA_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0b 00 00 "
		
	strings :
		$a_81_0 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 } //20 NanoCore Client
		$a_81_1 = {4b 65 79 62 6f 61 72 64 4c 6f 67 67 69 6e 67 } //1 KeyboardLogging
		$a_81_2 = {2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 48 6f 73 74 } //1 .ClientPluginHost
		$a_81_3 = {43 6c 69 65 6e 74 49 6e 76 6f 6b 65 44 65 6c 65 67 61 74 65 } //1 ClientInvokeDelegate
		$a_81_4 = {50 69 70 65 43 72 65 61 74 65 64 } //1 PipeCreated
		$a_81_5 = {67 65 74 5f 43 6c 69 65 6e 74 53 65 74 74 69 6e 67 73 } //1 get_ClientSettings
		$a_81_6 = {67 65 74 5f 43 6f 6e 6e 65 63 74 65 64 } //1 get_Connected
		$a_81_7 = {4d 79 2e 43 6f 6d 70 75 74 65 72 } //1 My.Computer
		$a_81_8 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_81_9 = {4d 4f 4e 45 59 20 4d 45 4e 2d 24 24 24 24 } //1 MONEY MEN-$$$$
		$a_81_10 = {42 79 70 61 73 73 55 73 65 72 41 63 63 6f 75 6e 74 43 6f 6e 74 72 6f 6c } //1 BypassUserAccountControl
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=25
 
}
rule Trojan_BAT_NanoCore_DA_MTB_2{
	meta:
		description = "Trojan:BAT/NanoCore.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 48 4f 75 50 6d 66 47 4f 56 69 34 4c 47 37 4f 64 48 36 30 4a 57 79 46 56 6e 6d 75 4c 32 } //1 RHOuPmfGOVi4LG7OdH60JWyFVnmuL2
		$a_81_1 = {6d 4a 58 4c 30 58 6d 53 34 4f 33 66 4b 65 32 4f 70 4d 7a 6e 4d 63 6e 36 43 42 6d 66 46 63 48 36 31 63 55 58 4f 59 31 36 6b 4f 6d 66 74 5a 57 57 77 41 6d 50 46 63 32 61 34 63 57 58 4f 59 31 57 54 4b 32 } //1 mJXL0XmS4O3fKe2OpMznMcn6CBmfFcH61cUXOY16kOmftZWWwAmPFc2a4cWXOY1WTK2
		$a_81_2 = {4f 4c 45 4f 7a 4c 6d 66 54 57 47 7a 6d 47 47 66 4b 63 31 6d 70 4f 47 76 46 63 44 47 63 4c 6d 61 51 63 47 } //1 OLEOzLmfTWGzmGGfKc1mpOGvFcDGcLmaQcG
		$a_81_3 = {70 46 56 4c 45 5a 47 4f 70 49 32 33 46 4c 47 32 34 50 6c 33 6f 59 6e 69 76 4c 32 7a 66 55 32 57 77 4b 32 76 46 4c 46 6d 34 50 6b 62 4b 59 32 76 6d 65 7a 57 65 4c 6a 4c 6d 43 33 48 59 63 6d 65 } //1 pFVLEZGOpI23FLG24Pl3oYnivL2zfU2WwK2vFLFm4PkbKY2vmezWeLjLmC3HYcme
		$a_81_4 = {4a 65 33 4f 59 4d 6e 4c 48 65 48 69 34 4f 44 6e 4a 64 6d 69 34 4a 6e 54 47 4c 48 6d 77 4a 57 6e 4f 59 32 2b 75 50 67 3d 3d } //1 Je3OYMnLHeHi4ODnJdmi4JnTGLHmwJWnOY2+uPg==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}