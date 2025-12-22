
rule Trojan_Linux_CobaltStrike_I_MTB{
	meta:
		description = "Trojan:Linux/CobaltStrike.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2f 63 6f 6d 6d 61 6e 64 2e 70 61 72 73 65 43 6f 6d 6d 61 6e 64 55 70 6c 6f 61 64 } //1 main/command.parseCommandUpload
		$a_01_1 = {6d 61 69 6e 2f 63 6f 6d 6d 61 6e 64 2e 70 6f 72 74 46 6f 72 77 61 72 64 53 65 72 76 65 } //1 main/command.portForwardServe
		$a_01_2 = {6d 61 69 6e 2f 70 61 63 6b 65 74 2e 50 75 6c 6c 43 6f 6d 6d 61 6e 64 } //1 main/packet.PullCommand
		$a_01_3 = {2f 63 6f 6d 6d 61 6e 64 2f 70 6f 72 74 5f 66 6f 72 77 61 72 64 2e 67 6f } //1 /command/port_forward.go
		$a_01_4 = {6d 61 69 6e 2f 63 6f 6d 6d 61 6e 64 2e 70 61 72 73 65 43 6f 6d 6d 61 6e 64 53 68 65 6c 6c } //1 main/command.parseCommandShell
		$a_01_5 = {6d 61 69 6e 2f 63 6f 6d 6d 61 6e 64 2e 55 70 6c 6f 61 64 } //1 main/command.Upload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}