
rule Backdoor_MacOS_ChillyHell_A_MTB{
	meta:
		description = "Backdoor:MacOS/ChillyHell.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 64 75 6c 65 42 61 63 6b 63 6f 6e 6e 65 63 74 53 68 65 6c 6c } //1 ModuleBackconnectShell
		$a_01_1 = {55 6e 6b 6e 6f 77 6e 53 65 72 76 69 63 65 4d 61 6e 61 67 65 72 49 6e 73 74 61 6c 6c 4c 6f 67 69 63 } //1 UnknownServiceManagerInstallLogic
		$a_01_2 = {49 73 49 6e 73 74 61 6c 6c 65 64 41 73 44 61 65 6d 6f 6e } //1 IsInstalledAsDaemon
		$a_01_3 = {49 6e 73 74 61 6c 6c 54 6f 53 68 65 6c 6c } //1 InstallToShell
		$a_01_4 = {43 72 65 61 74 65 53 65 72 76 69 63 65 4d 61 6e 61 67 65 72 4c 6f 61 64 43 6f 6d 6d 61 6e 64 } //1 CreateServiceManagerLoadCommand
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}