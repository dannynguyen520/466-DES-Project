#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

 /*
 * des takes two arguments on the command line:
 *    des -enc -ecb      -- encrypt in ECB mode
 *    des -enc -ctr      -- encrypt in CTR mode
 *    des -dec -ecb      -- decrypt in ECB mode
 *    des -dec -ctr      -- decrypt in CTR mode
 * des also reads some hardcoded files:
 *    message.txt            -- the ASCII text message to be encrypted,
 *                              read by "des -enc"
 *    encrypted_msg.bin      -- the encrypted message, a binary file,
 *                              written by "des -enc"
 *    decrypted_message.txt  -- the decrypted ASCII text message
 *    key.txt                -- just contains the key, on a line by itself, as an ASCII 
 *                              hex number, such as: 0x34FA879B
*/

/////////////////////////////////////////////////////////////////////////////
// Type definitions
/////////////////////////////////////////////////////////////////////////////
typedef uint64_t KEYTYPE;
typedef uint32_t SUBKEYTYPE;
typedef uint64_t BLOCKTYPE;

struct BLOCK {
    BLOCKTYPE block;        // the block read
    int size;               // number of "real" bytes in the block, should be 8, unless it's the last block
    struct BLOCK *next;     // pointer to the next block
};
typedef struct BLOCK* BLOCKLIST;

/////////////////////////////////////////////////////////////////////////////
// Initial and final permutation
/////////////////////////////////////////////////////////////////////////////
uint64_t init_perm[] = {
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,
	64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7
};

int final_perm[] = {
	40,8,48,16,56,24,64,32,
	39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30,
	37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28,
	35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26,
	33,1,41,9, 49,17,57,25
};

/////////////////////////////////////////////////////////////////////////////
// Subkey generation
/////////////////////////////////////////////////////////////////////////////
//There are 16 hardcoded keys
uint64_t hardcoded_subkeys[] = 
{
	0x1b02effc7072,
	0x79aed9dbc9e5,
	0x55fc8a42cf99,
	0x72add6db351d,
	0x7cec07eb53a8,
	0x63a53e507b2f,
	0xec84b7f618bc,
	0xf78a3ac13bfb,
	0xe0dbebede781,
	0xB1F347BA464F,
	0x215FD3DED386,
	0x7571F59467E9,
	0x97C5D1FABA41,
	0x5F43B7F2E73A,
	0xBF918D3D3F0A,
	0xCB3D8B0E17F5, 
};

// Each subkey is 48 bits. To simplify the assignment we're hardcoding keys here.
// Note that this means that the key argument to this assignment doesn't matter at
// all, since the subkeys are generated from the input key!
uint64_t getSubKey(int i) {
   return hardcoded_subkeys[i];
}

// For extra credit, write the key expansion routine.
void generateSubKeys(KEYTYPE key) {
   // TODO for extra credit
}

/////////////////////////////////////////////////////////////////////////////
// P-boxes
/////////////////////////////////////////////////////////////////////////////
uint64_t expand_box[] = {
	32,1,2,3,4,5,4,5,6,7,8,9,
	8,9,10,11,12,13,12,13,14,15,16,17,
	16,17,18,19,20,21,20,21,22,23,24,25,
	24,25,26,27,28,29,28,29,30,31,32,1
};

uint32_t Pbox[] = 
{
	16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
	2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25,
};		

/////////////////////////////////////////////////////////////////////////////
// S-boxes
/////////////////////////////////////////////////////////////////////////////
uint64_t sbox_1[4][16] = {
	{14,  4, 13,  1,  2, 15, 11,  8,  3, 10 , 6, 12,  5,  9,  0,  7},
	{ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
	{ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
	{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}};

uint64_t sbox_2[4][16] = {
	{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5 ,10},
	{ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
	{ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
	{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}};

uint64_t sbox_3[4][16] = {
	{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
	{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
	{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
	{ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}};


uint64_t sbox_4[4][16] = {
	{ 7, 13, 14,  3,  0 , 6,  9, 10,  1 , 2 , 8,  5, 11, 12,  4 ,15},
	{13,  8, 11,  5,  6, 15,  0,  3,  4 , 7 , 2, 12,  1, 10, 14,  9},
	{10,  6,  9 , 0, 12, 11,  7, 13 ,15 , 1 , 3, 14 , 5 , 2,  8,  4},
	{ 3, 15,  0,  6, 10,  1, 13,  8,  9 , 4 , 5, 11 ,12 , 7,  2, 14}};
 
 
uint64_t sbox_5[4][16] = {
	{ 2, 12,  4,  1 , 7 ,10, 11,  6 , 8 , 5 , 3, 15, 13,  0, 14,  9},
	{14, 11 , 2 ,12 , 4,  7, 13 , 1 , 5 , 0, 15, 10,  3,  9,  8,  6},
	{ 4,  2 , 1, 11, 10, 13,  7 , 8 ,15 , 9, 12,  5,  6 , 3,  0, 14},
	{11,  8 ,12 , 7 , 1, 14 , 2 ,13 , 6 ,15,  0,  9, 10 , 4,  5,  3}};


uint64_t sbox_6[4][16] = {
	{12,  1, 10, 15 , 9 , 2 , 6 , 8 , 0, 13 , 3 , 4 ,14 , 7  ,5 ,11},
	{10, 15,  4,  2,  7, 12 , 9 , 5 , 6,  1 ,13 ,14 , 0 ,11 , 3 , 8},
	{ 9, 14 ,15,  5,  2,  8 ,12 , 3 , 7 , 0,  4 ,10  ,1 ,13 ,11 , 6},
	{ 4,  3,  2, 12 , 9,  5 ,15 ,10, 11 ,14,  1 , 7  ,6 , 0 , 8 ,13}};
 

uint64_t sbox_7[4][16] = {
	{ 4, 11,  2, 14, 15,  0 , 8, 13, 3,  12 , 9 , 7,  6 ,10 , 6 , 1},
	{13,  0, 11,  7,  4 , 9,  1, 10, 14 , 3 , 5, 12,  2, 15 , 8 , 6},
	{ 1 , 4, 11, 13, 12,  3,  7, 14, 10, 15 , 6,  8,  0,  5 , 9 , 2},
	{ 6, 11, 13 , 8,  1 , 4, 10,  7,  9 , 5 , 0, 15, 14,  2 , 3 ,12}};
 
uint64_t sbox_8[4][16] = {
	{13,  2,  8,  4,  6 ,15 ,11,  1, 10,  9 , 3, 14,  5,  0, 12,  7},
	{ 1, 15, 13,  8 ,10 , 3  ,7 , 4, 12 , 5,  6 ,11,  0 ,14 , 9 , 2},
	{ 7, 11,  4,  1,  9, 12, 14 , 2,  0  ,6, 10 ,13 ,15 , 3  ,5  ,8},
	{ 2,  1, 14 , 7 , 4, 10,  8, 13, 15, 12,  9,  0 , 3,  5 , 6 ,11}};

void print_bits(BLOCKTYPE x)
{
    int i;
    for(i=8*sizeof(x)-1; i>=0; i--) {
        (x & (1 << i)) ? putchar('1') : putchar('0');
    }
    printf("\n");
}

/////////////////////////////////////////////////////////////////////////////
// I/O
/////////////////////////////////////////////////////////////////////////////

// Pad the list of blocks, so that every block is 64 bits, even if the
// file isn't a perfect multiple of 8 bytes long. In the input list of blocks,
// the last block may have "size" < 8. In this case, it needs to be padded. See 
// the slides for how to do this (the last byte of the last block 
// should contain the number if real bytes in the block, add an extra block if
// the file is an exact multiple of 8 bytes long.) The returned
// list of blocks will always have the "size"-field=8.
// Example:
//    1) The last block is 5 bytes long: [10,20,30,40,50]. We pad it with 2 bytes,
//       and set the length to 5: [10,20,30,40,50,0,0,5]. This means that the 
//       first 5 bytes of the block are "real", the last 3 should be discarded.
//    2) The last block is 8 bytes long: [10,20,30,40,50,60,70,80]. We keep this 
//       block as is, and add a new final block: [0,0,0,0,0,0,0,0]. When we decrypt,
//       the entire last block will be discarded since the last byte is 0
BLOCKLIST pad_last_block(BLOCKLIST blocks) {
    // TODO
	int pad = 0;
	BLOCKLIST walker = blocks;
	while (walker->next != NULL) {
		walker = walker->next;
	}
	//Last Block
	//Case 1: Last block is too short, pad it
	if (walker->size < 8) {
		pad = 8 - walker->size;
//		for (int i=0; i<pad-1; i++) {
//			walker->block[walker->size + i] = 0;
			walker->block = walker->block<<((pad-1)*8);
//		}
//		walker->block[walker->size - 1] = walker->size;
		BLOCKTYPE realBytes = walker->size;
		walker->block = walker->block<<8;
		walker->block |= realBytes;
	//Case 2: Last block is 8 bytes exactly, make a empty block
	} else {
		BLOCKLIST finalBlock = 0;
		walker->next = finalBlock;
	}
   return blocks;
}

// Reads the message to be encrypted, an ASCII text file, and returns a linked list 
// of BLOCKs, each representing a 64 bit block. In other words, read the first 8 characters
// from the input file, and convert them (just a C cast) to 64 bits; this is your first block.
// Continue to the end of the file.
BLOCKLIST read_cleartext_message(FILE *msg_fp) {
    // TODO
	BLOCKLIST head = NULL;
	BLOCKLIST walker;
	char str[8];
	int numElements = 0;
	int c = 0;
	int index = 0;
//	int blockIndex = 0;
	if (msg_fp) {
		while ((c = fgetc(msg_fp)) != -1) {
			printf("inside while index=%d\n",index);
			printf("Read char: %c\n", c);
			str[index % 8] = c;
			numElements++;
			index++;
			if (index == 8) {
				printf("index was 8, creating first block\n");
				printf("INSETING string: %s\n", str);
				walker->block = *((uint64_t *) str);
				walker->size = numElements;
				walker->next = NULL;
				numElements = 0;
				head = walker;
				memset(str, 0, strlen(str));
			} else if (index != 0 && index % 8 == 0) {
				printf("creating next block\n");
				walker->next = malloc(sizeof(BLOCKLIST));
				walker = walker->next;
				printf("INSETING string: %s\n", str);
				walker->block = *( (uint64_t *) str);
				walker->size = numElements;
				walker->next = NULL;
				numElements = 0;
				memset(str, 0, strlen(str));
			}
		}
		//File has less than 8 chars
		if (index < 7) {
			printf("file has less than 8 chars\n");
			walker->block = *((uint64_t *) str);
			walker->size = numElements;
			walker->next = head;
			numElements = 0;
			head = walker;
			memset(str, 0, strlen(str));
		} else {
			if (head->next == NULL) {
				walker = malloc(sizeof(BLOCKLIST));
				walker->block = *( (uint64_t *) str);
				walker->size = numElements;
				walker->next = NULL;
				numElements = 0;
				memset(str, 0, strlen(str));
				head->next = walker;
			} else {
				printf("creating next block\n");
				walker = walker->next;
				walker = malloc(sizeof(BLOCKLIST));
				walker->block = *( (uint64_t *) str);
				walker->size = numElements;
				walker->next = NULL;
				numElements = 0;
				memset(str, 0, strlen(str));
			}
		}
	}
	printf("Exiting loop\n");
    // call pad_last_block() here to pad the last block!
	head = pad_last_block(head);
	printf("Done padding\n");
	fclose(msg_fp);
   return head;
}

// Reads the encrypted message, and returns a linked list of blocks, each 64 bits. 
// Note that, because of the padding that was done by the encryption, the length of 
// this file should always be a multiople of 8 bytes. The output is a linked list of
// 64-bit blocks.
BLOCKLIST read_encrypted_file(FILE *msg_fp) {

	BLOCKLIST head = NULL;
	BLOCKLIST walker;
	msg_fp = fopen("encrypted.bin", "rb");
	BLOCKTYPE buffer;
	size_t bytes;
	if (msg_fp) {
//		bytes = fread(&buffer, 1, 8, msg_fp);
//		while ((c = fgetc(msg_fp)) != -1) {
//			printf("char grabbed: %d\n", c);
//
//		}
//		printf("size of BLOCKTYPE: %d\n", sizeof(BLOCKTYPE));
//		printf("read size: %d\n", bytes);
//		printf("buffer = %llx", buffer);
		while ((bytes = fread(&buffer, 1, 8, msg_fp)) > 0 ) {
//			printf("buffer = %llx\n", buffer);
//			printf("bytes read = %d\n", bytes);
			if (head == NULL) {
				head = malloc(sizeof(BLOCKLIST));
				head->block = buffer;
				head->next = NULL;
				head->size = bytes;
			} else if (head->next == NULL) {
				walker = malloc(sizeof(BLOCKLIST));
				walker->block = buffer;
				walker->next = NULL;
				walker->size = bytes;
				head->next = walker;
			} else {
				walker = head;
				while (walker != NULL) {
					walker = walker->next;
				}
				walker = malloc(sizeof(BLOCKLIST));
				walker->block = buffer;
				walker->next = NULL;
				walker->size = bytes;
			}
		}
	}
	fclose(msg_fp);
   return head;
}

// Reads 56-bit key into a 64 bit unsigned int. We will ignore the most significant byte,
// i.e. we'll assume that the top 8 bits are all 0. In real DES, these are used to check 
// that the key hasn't been corrupted in transit. The key file is ASCII, consisting of
// exactly one line. That line has a single hex number on it, the key, such as 0x08AB674D9.
KEYTYPE read_key(FILE *key_fp) {
    // TODO
   return 0;
}

// Write the encrypted blocks to file. The encrypted file is in binary, i.e., you can
// just write each 64-bit block directly to the file, without any conversion.
void write_encrypted_message(FILE *msg_fp, BLOCKLIST msg) {
    // TODO
	msg_fp = fopen("encrypted.bin","wb");

	if (msg_fp) {
		BLOCKLIST walker = msg;
		while (walker != NULL) {
//				fprintf(msg_fp, msg->block);
			fwrite(&walker->block, sizeof(walker->block), 1, msg_fp);
			walker = walker->next;
		}
	}
	fclose(msg_fp);
}

// Write the encrypted blocks to file. This is called by the decryption routine.
// The output file is a plain ASCII file, containing the decrypted text message.
void write_decrypted_message(FILE *msg_fp, BLOCKLIST msg) {
    // TODO

}

/////////////////////////////////////////////////////////////////////////////
// Encryption
/////////////////////////////////////////////////////////////////////////////

BLOCKTYPE initPermute(BLOCKTYPE b){
	printf("Before permutate----------------\n");
	printf("    Hex: %016llx\n", b);

    BLOCKTYPE masked;
    BLOCKTYPE thebit;
	BLOCKTYPE newBlock = 0;
	BLOCKTYPE mask;
	for (int i=0; i<64; i++) {
		mask =  1 << (63 - init_perm[i]);
		masked = b & mask;
		thebit = masked >> (63 - init_perm[i]);
		newBlock |= thebit;
		newBlock = newBlock << 1;
	}
	for(int i = 63; i >= 0; i--){
		mask =  1 << i;
		BLOCKTYPE masked_n = newBlock & mask;
		thebit = masked_n >> i;
		printf("%d", thebit);

  	}
printf("\n");
	// BLOCKTYPE p = newBlock;
	// newBlock = 0;
	// for (int i=0; i<64; i++) {
	// 	mask =  1 << (63-final_perm[i]-1);
	// 	masked = p & mask;
	// 	thebit = masked >> (63-final_perm[i]-1);
	// 	newBlock |= thebit;
	// 	newBlock = newBlock << 1;
	// }

	
	printf("After permutate---------------\n");
	printf("    Hex: %016llx\n", newBlock);
//	print_bits(newBlock);
	return newBlock;
}

BLOCKTYPE expand(BLOCKTYPE right) {
	BLOCKTYPE newRight = 0;
	BLOCKTYPE temp = 0;
	BLOCKTYPE mask = 1;
	int i;
	for (i=0; i<48; i++) {
		mask = mask<<(expand_box[i]-1);
		temp = mask & right;
		temp = temp>>(expand_box[i]-1);
		newRight |= temp;
		temp = 0;
		mask = 1;
	}

	return newRight;
}

BLOCKTYPE f_function(BLOCKTYPE right, BLOCKTYPE key) {
//  1.expand right
	right = expand(right);
//	2.XOR the expanded R and the compressed key,
	right = right ^ key;

//	3.Send the result through 8 S-boxes using the S-Box
//	Substitution to get 32 new bits,
	BLOCKTYPE inputBlock = 0;
	BLOCKTYPE mask6Bit = 0;
	int i;
	mask6Bit = 1;
	for (i=0; i<5; i++) {
		mask6Bit = mask6Bit << 1;
		mask6Bit += 1;
	}
	int row = 0;
	int col = 0;

	sbox_1[4][16];

//	4. Permute the result using the P-Box Permutation

}

// Encrypt one block. This is where the main computation takes place. It takes
// one 64-bit block as input, and returns the encrypted 64-bit block. The
// subkeys needed by the Feistel Network is given by the function getSubKey(i).
BLOCKTYPE des_enc(BLOCKTYPE v){
	// TODO
	//Step 1: Initially Permutate the block
	v = initPermute(v);
	//Step 2: Split the block into left and right
	BLOCKTYPE left = 0;
	BLOCKTYPE right = 0;
	BLOCKTYPE mask = 1;
	BLOCKTYPE mask2 = (1<<32);
	//put the first half of the bits with the left and the other half with the right
	int i;
	for (i=0; i<32; i++) {
		right = v & mask;
		left = v & mask2;
		mask = mask << 1;
		mask2 = mask2 << 1;
	}
//	right |= (uint32_t)v;
//	left |= (v>>32);
//	printf("Left:");
//	print_bits(right);
//	printf("Right:");
//	print_bits(left);
	//Step 3: 16 rounds of encrypting
	for (i=0; i<16; i++) {
		//left
	}

   return v;
}

// Encrypt the blocks in ECB mode. The blocks have already been padded 
// by the input routine. The output is an encrypted list of blocks.
BLOCKLIST des_enc_ECB(BLOCKLIST msg) {
    // TODO
	BLOCKLIST walker = msg;
	while (walker != NULL) {
		walker->block = des_enc(walker->block);
		walker = walker->next;
	}
    // Should call des_enc in here repeatedly
   return msg;
}

// Same as des_enc_ECB, but encrypt the blocks in Counter mode.
// SEE: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
// Start the counter at 0.
BLOCKLIST des_enc_CTR(BLOCKLIST msg) {
    // TODO
    // Should call des_enc in here repeatedly
   return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// Decryption
/////////////////////////////////////////////////////////////////////////////
// Decrypt one block.
BLOCKTYPE des_dec(BLOCKTYPE v){
    // TODO
   return 0;
}

// Decrypt the blocks in ECB mode. The input is a list of encrypted blocks,
// the output a list of plaintext blocks.
BLOCKLIST des_dec_ECB(BLOCKLIST msg) {
    // TODO
    // Should call des_dec in here repeatedly
   return NULL;
}

// Decrypt the blocks in Counter mode
BLOCKLIST des_dec_CTR(BLOCKLIST msg) {
    // TODO
    // Should call des_enc in here repeatedly
   return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// Main routine
/////////////////////////////////////////////////////////////////////////////

//void encrypt (int argc, char **argv) {
//      FILE *msg_fp = fopen("message.txt", "r");
//      BLOCKLIST msg = read_cleartext_message(msg_fp);
//      fclose(msg_fp);
//
//      BLOCKLIST encrypted_message;
//      if (!strcmp(argv[2], "-ecb")) {
//         encrypted_message = des_enc_ECB(msg);
//      } else if (!strcmp(argv[2], "-ctr")) {
//         encrypted_message = des_enc_CTR(msg);
//      } else {
//         printf("No such mode.\n");
//      };
//      FILE *encrypted_msg_fp = fopen("encrypted_msg.bin", "wb");
//      write_encrypted_message(encrypted_msg_fp, encrypted_message);
//      fclose(encrypted_msg_fp);
//}
//
//void decrypt (int argc, char **argv) {
////      FILE *encrypted_msg_fp = fopen("encrypted_msg.bin", "wb");
//	  FILE *encrypted_msg_fp = fopen("encrypted_msg.bin", "r");
//      BLOCKLIST encrypted_message = read_encrypted_file(encrypted_msg_fp);
//      fclose(encrypted_msg_fp);
//
//      BLOCKLIST decrypted_message;
//      if (!strcmp(argv[2], "-ecb")) {
//         decrypted_message = des_dec_ECB(encrypted_message);
//      } else if (!strcmp(argv[2], "-ctr")) {
//         encrypted_message = des_dec_CTR(encrypted_message);
//      } else {
//         printf("No such mode.\n");
//      };
//
////      FILE *decrypted_msg_fp = fopen("decrypted_message.txt", "r");
//      FILE *decrypted_msg_fp = fopen("decrypted_message.txt", "wb");
//      write_decrypted_message(decrypted_msg_fp, decrypted_message);
//      fclose(decrypted_msg_fp);
//}


int main(int argc, char **argv){
	//-----------------TESTING----------------------
	FILE *msg_fp = fopen("message.txt", "r");
	printf("blah\n");
	BLOCKLIST head = read_cleartext_message(msg_fp);
	int block = 1;
	BLOCKLIST msg = head;
	printf("\n\n====================read_cleartext_message:===========================\n");
	while (msg != NULL) {
		printf("Block %d:----------------------------\n", block);
		printf("Decimal: %016lld\n", msg->block);
		printf("    Hex: %016llx\n", msg->block);
		msg = msg->next;
		block++;
	}

	printf("\n\n==================des_enc_ECB:==============================\n");
	BLOCKLIST enc_msg = des_enc_ECB(head);




	write_encrypted_message(msg_fp, head);
	block = 0;
	BLOCKLIST msg2 = read_encrypted_file(msg_fp);
	printf("\n\n====================read_encrypted_file:================================\n");
	while (msg2 != NULL) {
		printf("Block %d:----------------------------\n", block);
		printf("Decimal: %016lld\n", msg2->block);
		printf("    Hex: %016llx\n", msg2->block);
		msg2 = msg2->next;
		block++;
	}

	fclose(msg_fp);
	//--------------------------------------------------


//   FILE *key_fp = fopen("key.txt","r");
//   KEYTYPE key = read_key(key_fp);
//   generateSubKeys(key);              // This does nothing right now.
//   fclose(key_fp);
//
//   if (!strcmp(argv[1], "-enc")) {
//      encrypt(argc, argv);
//   } else if (!strcmp(argv[1], "-dec")) {
//      decrypt(argc, argv);
//   } else {
//     printf("First argument should be -enc or -dec\n");
//   }
   return 0;
}
