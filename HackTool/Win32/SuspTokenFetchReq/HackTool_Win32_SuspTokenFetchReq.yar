
rule HackTool_Win32_SuspTokenFetchReq{
	meta:
		description = "HackTool:Win32/SuspTokenFetchReq,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 00 6f 00 61 00 64 00 74 00 78 00 20 00 } //5 roadtx 
		$a_00_1 = {61 00 70 00 70 00 61 00 75 00 74 00 68 00 20 00 } //5 appauth 
		$a_00_2 = {61 00 61 00 64 00 67 00 72 00 61 00 70 00 68 00 } //5 aadgraph
		$a_00_3 = {2d 00 2d 00 63 00 65 00 72 00 74 00 2d 00 70 00 66 00 78 00 } //1 --cert-pfx
		$a_00_4 = {2d 00 2d 00 70 00 66 00 78 00 2d 00 70 00 61 00 73 00 73 00 } //1 --pfx-pass
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=16
 
}