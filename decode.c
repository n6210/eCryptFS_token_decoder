/*
	eCryptFS Token Decoder tool
	(C) 2019 Taddy Snow fotonix@pm.me
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/types.h>

#define ECRYPTFS_SIG_SIZE 8
#define ECRYPTFS_SIG_SIZE_HEX (ECRYPTFS_SIG_SIZE*2)
#define ECRYPTFS_PASSWORD_SIG_SIZE ECRYPTFS_SIG_SIZE_HEX
#define ECRYPTFS_MAX_KEY_BYTES 64
#define ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES 512
#define ECRYPTFS_SALT_SIZE 8
#define ECRYPTFS_MAX_KEY_MOD_NAME_BYTES 16

enum ecryptfs_token_types {ECRYPTFS_PASSWORD, ECRYPTFS_PRIVATE_KEY};

struct ecryptfs_private_key {
	uint32_t key_size;
	uint32_t data_len;
	uint8_t signature[ECRYPTFS_PASSWORD_SIG_SIZE + 1];
	char key_mod_alias[ECRYPTFS_MAX_KEY_MOD_NAME_BYTES + 1];
	uint8_t data[];
};

struct ecryptfs_session_key {
#define ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT 0x00000001
#define ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT 0x00000002
#define ECRYPTFS_CONTAINS_DECRYPTED_KEY 0x00000004
#define ECRYPTFS_CONTAINS_ENCRYPTED_KEY 0x00000008
	int32_t flags;
	int32_t encrypted_key_size;
	int32_t decrypted_key_size;
	uint8_t encrypted_key[ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES];
	uint8_t decrypted_key[ECRYPTFS_MAX_KEY_BYTES];
};

struct ecryptfs_password {
	int32_t password_bytes;
	int32_t hash_algo;
	int32_t hash_iterations;
	int32_t session_key_encryption_key_bytes;
#define ECRYPTFS_PERSISTENT_PASSWORD             0x01
#define ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET  0x02
	uint32_t flags;
	/* Iterated-hash concatenation of salt and passphrase */
	uint8_t session_key_encryption_key[ECRYPTFS_MAX_KEY_BYTES];
	uint8_t signature[ECRYPTFS_PASSWORD_SIG_SIZE + 1];
	/* Always in expanded hex */
	uint8_t salt[ECRYPTFS_SALT_SIZE];
};

struct ecryptfs_auth_tok {
	uint16_t version; /* 8-bit major and 8-bit minor */
	uint16_t token_type;
#define ECRYPTFS_ENCRYPT_ONLY 0x00000001
	uint32_t flags;
	struct ecryptfs_session_key session_key;
	uint8_t reserved[32];
	union {
		struct ecryptfs_password password;
		struct ecryptfs_private_key private_key;
	} token;
}  __attribute__ ((packed));

struct ecryptfs_auth_tok tok;



int read_token(char *fname, void *data, int len)
{
	int f, ret;
	unsigned char *data_p = data;
	
	f = open(fname, O_RDONLY);
	if (f < 0) {
		printf("%s\n", strerror(errno));
		return (-1);
	}

	ret = read(f, data_p, len);
	if (ret != len) {
		printf("%s\n", strerror(errno));
		return (-2);
	}
	
	close(f);
	
	printf("Read %d (ret=%d)\n", len, ret);
}

int save_key(char *signature, void *data, int len)
{
	int f;
	char *fname;
	
	asprintf(&fname, "%s.key", signature);
	printf("Save key to file [%s] %d bytes\n", fname, len);
	
	f = open(fname, O_CREAT | O_WRONLY, 0666);
	if (f < 0) {
		printf("%s\n", strerror(errno));
	}
	write(f, data, len);
	if (f < 0) {
		printf("%s\n", strerror(errno));
	}
	close(f);
	free(fname);
}

ph(char *txt, void *buf, int len, char *txtend)
{
	int i;
	unsigned char *p = buf;
	
	printf("%s", txt);
	
	for (i = 0; i < len; i++)
		printf("%02X", p[i]);
	
	printf("%s", txtend);
}

int main(int argc, char **argv)
{
	int f, size = sizeof(tok);

	if (argc < 2) {
		printf("Input file name missing\n");
		return 1;
	}
	
	read_token(argv[1], &tok, size);
	
	printf("VERSION: %04X\n", tok.version);
	printf("TTYPE  : %s\n", (tok.token_type == ECRYPTFS_PASSWORD)?"PASSWORD":"PRIVATE_KEY");
	printf("EKS    : %d\n", tok.session_key.encrypted_key_size);
	printf("DKS    : %d\n", tok.session_key.decrypted_key_size);
	printf("PLEN   : %d\n", tok.token.password.password_bytes);
	
	printf("HASHALG: %s\n", (tok.token.password.hash_algo & 0x0A)?"PGP_DIGEST_ALGO_SHA512":"?");
	printf("H-IETR : %d\n", tok.token.password.hash_iterations);
	printf("FLAGS  : %02X %s\n\n", tok.token.password.flags, (tok.token.password.flags & 2)?"SESION/ENCRYPTION KEY SET":"");
	
	printf("SES KEYLEN : %d\n", tok.token.password.session_key_encryption_key_bytes);
	ph("SESION KEY : ", &tok.token.password.session_key_encryption_key, tok.token.password.session_key_encryption_key_bytes, "\n");
	ph("SIGNATURE  : ", &tok.token.password.signature, ECRYPTFS_PASSWORD_SIG_SIZE, " -- ");
	printf("[%s]\n", tok.token.password.signature);
	ph("SALT       : ", &tok.token.password.salt, ECRYPTFS_SALT_SIZE, "\n");
	
	save_key(tok.token.password.signature, &tok.token.password.session_key_encryption_key, tok.token.password.session_key_encryption_key_bytes);
	
	return 0;
}
