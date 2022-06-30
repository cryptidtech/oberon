#ifndef __oberon__included__
#define __oberon__included__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct ByteBuffer {
    int64_t len;
    uint8_t *data;
} ByteBuffer;

typedef struct ByteArray {
    uintptr_t length;
    const uint8_t *data;
} ByteArray;

typedef struct ExternError {
    int32_t code;
    char* message;
} ExternError;

void oberon_string_free(char *s);
void oberon_byte_buffer_free(struct ByteBuffer v);
void oberon_create_proof_free(uint64_t handle, struct ExternError *err);

int32_t oberon_secret_key_size(void);
int32_t oberon_public_key_size(void);
int32_t oberon_token_size(void);
int32_t oberon_blinding_size(void);
int32_t oberon_proof_size(void);

int32_t oberon_new_secret_key(struct ByteBuffer secret_key);
int32_t oberon_get_public_key(struct ByteArray secret_key, struct ByteBuffer *public_key, struct ExternError *err);
int32_t oberon_secret_key_from_seed(struct ByteArray seed, struct ByteBuffer *secret_key);
int32_t oberon_new_token(struct ByteArray secret_key, struct ByteArray id, struct ByteBuffer *token, struct ExternError *err);
int32_t oberon_verify_token(struct ByteArray token, struct ByteArray public_key, struct ByteArray id, struct ExternError *err);
int32_t oberon_create_blinding(struct ByteArray data, struct ByteBuffer *blinding);
int32_t oberon_add_blinding(struct ByteArray old_token, struct ByteArray data, struct ByteBuffer *new_token, struct ExternError *err);
int32_t oberon_remove_blinding(struct ByteArray old_token, struct ByteArray data, struct ByteBuffer *new_token, struct ExternError *err);
uint64_t oberon_create_proof_init(struct ExternError *err);
int32_t oberon_create_proof_set_token(uint64_t handle, struct ByteArray token, struct ExternError *err);
int32_t oberon_create_proof_set_id(uint64_t handle, struct ByteArray id, struct ExternError *err);
int32_t oberon_create_proof_set_nonce(uint64_t handle, struct ByteArray nonce, struct ExternError *err);
int32_t oberon_create_proof_add_blinding(uint64_t handle, struct ByteArray blinding, struct ExternError *err);
int32_t oberon_create_proof_finish(uint64_t handle, struct ByteBuffer *proof, struct ExternError *err);
int32_t oberon_verify_proof(struct ByteArray proof, struct ByteArray public_key, struct ByteArray id, struct ByteArray nonce, struct ExternError *err);

#endif