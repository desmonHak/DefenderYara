
rule Trojan_Win64_LummaStealer_CB_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 52 65 64 69 72 65 63 74 54 6f 50 61 79 6c 6f 61 64 } //2 main.RedirectToPayload
		$a_01_1 = {6d 61 69 6e 2e 4c 6f 61 64 50 45 4d 6f 64 75 6c 65 } //1 main.LoadPEModule
		$a_01_2 = {6d 61 69 6e 2e 47 65 74 4e 54 48 64 72 73 } //1 main.GetNTHdrs
		$a_01_3 = {6d 61 69 6e 2e 41 6c 6c 6f 63 50 45 42 75 66 66 65 72 } //1 main.AllocPEBuffer
		$a_01_4 = {6d 61 69 6e 2e 50 45 52 61 77 54 6f 56 69 72 74 75 61 6c } //1 main.PERawToVirtual
		$a_01_5 = {6d 61 69 6e 2e 43 72 65 61 74 65 53 75 73 70 65 6e 64 65 64 50 72 6f 63 65 73 73 } //1 main.CreateSuspendedProcess
		$a_01_6 = {6d 61 69 6e 2e 5f 4c 6f 61 64 50 45 4d 6f 64 75 6c 65 } //1 main._LoadPEModule
		$a_01_7 = {6d 61 69 6e 2e 52 65 73 75 6d 65 5f 54 68 72 65 61 64 } //1 main.Resume_Thread
		$a_01_8 = {6d 61 69 6e 2e 57 72 69 74 65 5f 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 main.Write_ProcessMemory
		$a_01_9 = {6d 61 69 6e 2e 47 65 74 5f 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 main.Get_ThreadContext
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=11
 
}