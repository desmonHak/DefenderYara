
rule Trojan_Win32_Glupteba_A_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //1 MiniDumpWriteDump
		$a_00_1 = {44 69 73 63 6f 72 64 } //1 Discord
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {2e 49 73 45 6c 65 76 61 74 65 64 } //1 .IsElevated
		$a_81_4 = {6e 65 74 2f 68 74 74 70 2e 70 65 72 73 69 73 74 43 6f 6e 6e 57 72 69 74 65 72 2e 57 72 69 74 65 } //1 net/http.persistConnWriter.Write
		$a_01_5 = {6d 61 78 50 61 79 6c 6f 61 64 53 69 7a 65 46 6f 72 57 72 69 74 65 } //1 maxPayloadSizeForWrite
		$a_01_6 = {47 65 6f 49 50 } //1 GeoIP
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}