
rule HackTool_Win32_SuspUserEnumReq{
	meta:
		description = "HackTool:Win32/SuspUserEnumReq,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 } //5 curl 
		$a_00_1 = {2d 00 2d 00 6f 00 61 00 75 00 74 00 68 00 32 00 2d 00 62 00 65 00 61 00 72 00 65 00 72 00 20 00 } //5 --oauth2-bearer 
		$a_00_2 = {67 00 72 00 61 00 70 00 68 00 2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 } //5 graph.windows.net/
		$a_00_3 = {75 00 73 00 65 00 72 00 70 00 72 00 69 00 6e 00 63 00 69 00 70 00 61 00 6c 00 6e 00 61 00 6d 00 65 00 } //1 userprincipalname
		$a_00_4 = {6e 00 65 00 74 00 69 00 64 00 } //1 netid
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=16
 
}