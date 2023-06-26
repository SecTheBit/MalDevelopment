## Function call Obfuscation

The Function call such as VirtualAlloc(), RtlMoveMemory() , etc. can be obfuscated and used after Decrypting the it. Process Involved in this are:

- First Declare a Pointer to that Particular Function , VP , in this case.
- Encrypted the Function String, "VirtualProtect" in this case, using any encryption Method, XOR have been used here.
- Declare a char buffer containing the Encrypted String
- Use the GetProcessAddress to retrieve the address of the exported Function (VirtualProtect).
- Use the address of exported Function with all arguments as it is in the POC.
