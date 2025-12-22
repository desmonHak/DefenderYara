
rule HackTool_Win32_DumpGuard_A_MTB{
	meta:
		description = "HackTool:Win32/DumpGuard.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {44 75 6d 70 43 72 65 64 65 6e 74 69 61 6c 73 52 65 6d 6f 74 65 43 72 65 64 65 6e 74 69 61 6c 47 75 61 72 64 41 6c 6c } //1 DumpCredentialsRemoteCredentialGuardAll
		$a_01_1 = {4c 73 61 45 6e 75 6d 65 72 61 74 65 4c 6f 67 6f 6e 53 65 73 73 69 6f 6e 73 } //1 LsaEnumerateLogonSessions
		$a_01_2 = {64 6f 6d 61 69 6e } //1 domain
		$a_01_3 = {75 73 65 72 6e 61 6d 65 } //1 username
		$a_01_4 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_01_5 = {2e 4c 69 6e 6b 65 64 4c 69 73 74 } //1 .LinkedList
		$a_01_6 = {2e 4b 65 72 62 65 72 6f 73 2e 4e 65 74 77 6f 72 6b 69 6e 67 } //1 .Kerberos.Networking
		$a_01_7 = {2e 53 70 6e 65 67 6f } //1 .Spnego
		$a_01_8 = {2e 54 73 73 73 70 } //1 .Tsssp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}