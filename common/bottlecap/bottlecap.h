#ifndef __BOTTLECAP_H__
#define __BOTTLECAP_H__

#include <stdint.h>

#include "bottle.h"
#include "cap.h"
#include "crypto.h"

//BOTTLE CREATION/DELETION
/**
 * Initialises a new bottle, in the memory provided.
 * bottle.header.size and bottle.header.flags should be filled in
 * by the caller.
 * 
 * @param bottle Memory where the bottle is to be created.
 * @return       Error code.
 */
int32_t bottle_init(bottle_t* bottle);
/**
 * Destroys the given bottle.
 * At the moment simply zeros the relevant memory, but may in future
 * reclaim resources consumed by this bottle, such as TPM monotonic
 * counters.
 * 
 * @param bottle Memory where the bottle is to be created.
 * @return       Error code.
 */
int32_t bottle_destroy(bottle_t* bottle);

//BOTTLE STATE FUNCTIONS
/**
 * Returns the number of free slots in the bottle.
 * 
 * @param bottle The bottle to operate on.
 * @param slots  Output: The number of free slots in bottle.
 * @return       Error code.
 */
int32_t bottle_query_free_slots(bottle_t* bottle, uint32_t* slots);
/**
 * Deletes all caps in the bottle whose expiry dates
 * are less than or equal to time.
 * 
 * @param bottle The bottle to operate on.
 * @param time   The current time.
 * @param slots  Output: The new number of free slots in the bottle.
 * @return       Error code.
 */
int32_t bottle_expire(bottle_t* bottle, uint64_t time, uint32_t* slots);

//INTER-MACHINE BOTTLE MIGRATION FUNCTIONS
//TODO: these are left for later
/**
 * Binds this bottle's BRK to a new TPM (including PCR values),
 * allowing inter-machine migration.
 * Does not change bottle in any way.
 * 
 * @param bottle The bottle to operate on.
 * @param rsrk   The remote TPM's public SRK.
 * @param brk    Output: {BRK}_rSRK (TPM key blob, bound)
 * @return       Error code.
 */
//int32_t bottle_export(bottle_t* bottle, tpm_rsakey_t* rsrk, tpm_rsakey_t* brk);
/**
 * Imports a bottle onto this machine: takes the bound BRK, and uses it to
 * rewrite the bottle header so it is usable on this machine.
 * 
 * @param bottle The bottle to operate on.
 * @param brk    {BRK}_SRK for this machine's TPM
 * @return       Error code.
 */
//int32_t bottle_import(bottle_t* bottle, tpm_rsakey_t* brk);

//CAP INSERTION/DELETION FUNCTIONS
/**
 * Inserts a capability into the first free slot in the bottle.
 * 
 * @param bottle The bottle to operate on.
 * @param cap    {The new cap.}_BRK (bound)
 * @param slot   Output: The slot into which cap was inserted.
 * @return       Error code.
 */
int32_t bottle_cap_add(bottle_t* bottle, tpm_encrypted_cap_t* cap, uint32_t* slot);
/**
 * Deletes a capability from the specified slot. If the slot is empty,
 * this is a no-op.
 * 
 * @param bottle The bottle to operate on.
 * @param slot   The slot to clear.
 * @return       Error code.
 */
int32_t bottle_cap_delete(bottle_t* bottle, uint32_t slot);

//INTER-BOTTLE CAP MIGRATION
//TODO: left for later
/**
 * Exports a capability for migration to another bottle. (The remote
 * bottle uses bottle_cap_add to import it.)
 * 
 * TODO: for performance reasons, this will need to be able to export multiple caps
 * 
 * @param bottle The bottle to operate on.
 * @param slot   The slot containing the cap to export.
 * @param rbrk   The public BRK for the bottle to export to.
 * @param move   Boolean: whether to delete the original cap.
 * @param cap    Output: {Exported cap}_rBRK (bound)
 * @return       Error code.
 */
//int32_t bottle_cap_export(bottle_t* bottle, uint32_t slot, tpm_rsakey_t* rbrk, int32_t move, tpm_encrypted_cap_t* cap);

//CAP INVOCATION FUNCTIONS
#define ATTEST_MAGIC 0xA77E57EDCA900000ULL
/**
 * Data structure filled by bottle_cap_attest -- read the comment for that funtion
 * before going any further.
 */
typedef struct {
	uint128_t nonce; //nonce, in plaintext
	union {
		struct {
			uint64_t  oid;     //cap OID
			uint64_t  expiry;  //attestation block's expiry date
			uint64_t  amagic;  //0xA77E57EDCA90000
			uint32_t  urights; //rights mask enabled for this attestation block
			uint32_t  cmagic;  //0xCA9A817 -- CAP_MAGIC_TOP
		};
		unsigned char bytes[32];
	} authdata; //{authority data}_cap.issuer, using nonce as IV

	sha1hash_t hmac; //SHA1(authdata, issuer)

	uint64_t expiry;  //repeat of the same fields as above, in plaintext, for easy introspection.
	uint32_t urights; // should not be used by any security-sensitive code (which should be able
	                  // see the encrypted versions anyway)
} cap_attestation_block_t;

/**
 * Generates a proof of posession of a capability.
 * 
 * @param bottle  The bottle to operate on.
 * @param slot    The slot containing the cap to attest.
 * @param nonce   Public nonce value.
 * @param expiry  Expiry time of the issued authority block.
 * @param urights A mask of user rights to authorise for this block; must be a subset of the cap rights.
 * @param result  Output: cap attestation block described above.
 * @return        Error code.
 */
int32_t bottle_cap_attest(bottle_t* bottle, uint32_t slot, uint128_t nonce, uint64_t expiry, uint32_t urightsmask, cap_attestation_block_t* result);


//TODO: need some way for us to trust a remote SRK, for _export and _cap_export

#endif /* __BOTTLECAP_H__ */

