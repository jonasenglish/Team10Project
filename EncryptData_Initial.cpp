// EncryptData.cpp
//
// This file uses the input data and key information to encrypt the input data
//

#include "Main.h"

void encryptData_02(char* data, int datalength)
{
	int resulti = 0;

	__asm
	{
		//Keep the local variable
		mov eax, data //Keep the parameter before setting up the stack frame
		mov ecx, datalength
		mov edx, ebp

		//Set up the stack frame
		push ebp
		mov ebp, esp
		sub esp, 24

		//Store the parameter and initial value in a local variable		
		mov dword ptr[ebp - 4], eax//Data
		mov dword ptr[ebp - 8], ecx//DataLength
		xor ebx, ebx //Loop Variable (Offset) Stored at EBX

		//Save starting index as local variable
		//starting_index = gPasswordHash[0] * 256 + gPasswordHash[1];
		lea	esi, gPasswordHash //get the starting address of the password hash
		xor eax, eax //clear eax
		xor edx, edx //clear edx
		xor ecx, ecx //clear ecx
		mov al, byte ptr[esi] //get first byte of password hash
		mov cl, byte ptr[esi + 1] //get the second byte of the password hash
		imul eax, 256 //Multiply first byte by 256
		add eax, ecx //add the second byte
		mov dword ptr[ebp - 16], eax //store in a local variable

		//Get the gkey pointer
		mov esi, gptrKey
		mov dword ptr[ebp - 20], esi //store the key pointer

		//Get the gEncodeTable pointer
		lea esi, gEncodeTable
		mov dword ptr[ebp - 24], esi

		//Loop over the data buffer
		enc_loop :
		//Getting Byte
		mov eax, dword ptr[ebp - 4]  //get the data base pointer
			add eax, ebx //add the offset to the base
			mov dword ptr[ebp - 12], eax // Store Offset + Base
			mov dl, byte ptr[eax] //move the current byte to a register

				//Getting Key
			mov eax, dword ptr[ebp - 20] //get the key base pointer
			add eax, dword ptr[ebp - 16] //get the Starting_index, NOTE: Will need to be Index come milestone 2
			mov eax, dword ptr[eax] //move the current byte to a register
			and eax, 0000000FFh

				//XOR Byte with Key
			xor al, dl //xor the key and data byte

		//MILESTONE #2 Begins HERE
			//Team 10 Encryption Order: ECDAB

			//#E Rotate 3 Bits Left
			rol al, 3
			
			//#C Nibble Rotate Left 1 95 -> 3A
			xor edx, edx	//Clear
			xor ecx, ecx	//Clear
			mov cl, al		//Copy

			and al, 0F0h	//High Bit 
			shr al, 4		//Place into Nibble Low
			mov dl, al		//Move to DL for processing
			shr dl, 3		//Get rid of last 3 bits in DL
			shl al, 1		//Get rid of first bit in AL
			and al, 00Fh	//Dump that first bit
			add al, dl		//Put the "First bit" back into AL's Last bit slot

			and cl, 00Fh	//Low Bit
			mov dl, cl		//Move to DL for processing
			shr dl, 3		//Get rid of last 3 bits in DL
			shl cl, 1		//Get rid of first bit in CL
			and cl, 00Fh	//Dump that first bit	
			add cl, dl		//Put the "First bit" back into AL's Last bit slot					
			
			shl al, 4		//Put AL back into the First Nibble
			add al, cl		//Combine the two Nibbles AL, CL

			//#D Invert Bits 1 5 6
			xor al, 000110001b

			//#A Table Lookup
			mov ecx, dword ptr[ebp-24]	//Get table pointer
			add ecx, eax				//Add al to get correct position in table
			mov al, byte ptr[ecx]		//Get new byte from table

			//#B Reverse Bit order
			xor ecx, ecx //Clear
			xor edx, edx //Clear
			mov ecx, 8 //Set Count
			rev_loop :
				rcr al, 1 //Rotate Right
				rcl dl, 1 //Rotate Left
				loop rev_loop
			mov al, dl //Move Result back into al

		//MILESTONE #2 Ends HERE

				//Store the xor byte into the buffer				
			mov ecx, dword ptr[ebp - 12] // Retrieve Offset + Base
			mov byte ptr[ecx], al // Move the Result byte back into the data buffer

				//Increment and CMP for Loop.
			inc ebx //increment the offset
			cmp ebx, [ebp - 8] //compare to the data length
			jne enc_loop //Loop if more data needs to process

		//return stack frame
			mov esp, ebp
			pop ebp
	}

	return;
} // encryptData_02

void encryptData_01(char *data, int datalength)
{
	int resulti = 0;

	__asm
	{
		//Keep the local variable
		mov eax, data //Keep the parameter before setting up the stack frame
		mov ecx, datalength
		mov edx, ebp

		//Set up the stack frame
		push ebp
		mov ebp, esp
		sub esp, 20

		//Store the parameter and initial value in a local variable		
		mov dword ptr[ebp - 4], eax//Data
		mov dword ptr[ebp - 8], ecx//DataLength
		xor ebx, ebx //Loop Variable (Offset) Stored at EBX

		//Save starting index as local variable
		//starting_index = gPasswordHash[0] * 256 + gPasswordHash[1];
		lea	esi, gPasswordHash //get the starting address of the password hash
		xor eax, eax //clear eax
		xor edx, edx //clear edx
		xor ecx, ecx //clear ecx
		mov al, byte ptr[esi] //get first byte of password hash
		mov cl, byte ptr[esi + 1] //get the second byte of the password hash
		imul eax, 256 //Multiply first byte by 256
		add eax, ecx //add the second byte
		mov dword ptr[ebp - 16], eax //store in a local variable

		//Get the gkey pointer
		mov esi, gptrKey
		mov dword ptr[ebp - 20], esi //store the key pointer

		//Loop over the data buffer
		enc_loop :
		//Getting Byte
		mov eax, dword ptr[ebp - 4]  //get the data base pointer
			add eax, ebx //add the offset to the base
			mov dword ptr[ebp - 12], eax // Store Offset + Base
			mov dl, byte ptr[eax] //move the current byte to a register

				//Getting Key
			mov eax, dword ptr[ebp - 20] //get the key base pointer
			add eax, dword ptr[ebp - 16] //get the Starting_index, NOTE: Will need to be Index come milestone 2
			mov eax, dword ptr[eax] //move the current byte to a register

				//XOR Byte with Key
			xor al, dl //xor the key and data byte

				//Store the xor byte into the buffer				
			mov ecx, dword ptr[ebp - 12] // Retrieve Offset + Base
			mov byte ptr[ecx], al // Move the Result byte back into the data buffer

				//Increment and CMP for Loop.
			inc ebx //increment the offset
			cmp ebx, [ebp - 8] //compare to the data length
			jne enc_loop //Loop if more data needs to process

		//return stack frame
		mov esp, ebp
		pop ebp
	}

	return;
} // encryptData_01


int encryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					
	gdebug2 = 0;					
	__asm {
		nop
	}

	return resulti;
} // encryptData

