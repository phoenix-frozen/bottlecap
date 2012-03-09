#ifndef __BOTTLECAP_H__
#define __BOTTLECAP_H__

#include <stdint.h>

#include <bottlecap/errors.h>

#include "bottle.h"
#include "cap.h"
#include "tpm_crypto.h"

//BOTTLE CREATION/DELETION
/**
 * Initialises a new bottle, in the memory provided.
 * bottle.header.size and bottle.header.flags should be filled in
 * by the caller.
 * 
 * @param bottle Memory where the bottle is to be created.
 * @return       Error code.
 */
int32_t bottle_init(bottle_t bottle);
/**
 * Destroys the given bottle.
 * At the moment simply zeros the relevant memory, but may in future
 * reclaim resources consumed by this bottle, such as TPM monotonic
 * counters.
 * 
 * @param bottle Memory where the bottle is to be created.
 * @return       Error code.
 */
int32_t bottle_destroy(bottle_t bottle);

//BOTTLE STATE FUNCTIONS
/**
 * Returns the number of free slots in the bottle.
 * 
 * @param bottle The bottle to operate on.
 * @param slots  Output: The number of free slots in bottle.
 * @return       Error code.
 */
int32_t bottle_query_free_slots(bottle_t bottle, uint32_t* slots);
/**
 * Deletes all caps in the bottle whose expiry dates
 * are less than or equal to time.
 * 
 * @param bottle The bottle to operate on.
 * @param time   The current time.
 * @param slots  Output: The new number of free slots in the bottle.
 * @return       Error code.
 */
int32_t bottle_expire(bottle_t bottle, uint64_t time, uint32_t* slots);

//INTER-MACHINE BOTTLE MIGRATION FUNCTIONS
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
int32_t bottle_export(bottle_t bottle, tpm_rsakey_t* rsrk, tpm_rsakey_t* brk);
/**
 * Imports a bottle onto this machine: takes the bound BRK, and uses it to
 * rewrite the bottle header so it is usable on this machine.
 * 
 * @param bottle The bottle to operate on.
 * @param brk    {BRK}_SRK for this machine's TPM
 * @return       Error code.
 */
int32_t bottle_import(bottle_t bottle, tpm_rsakey_t* brk);

//CAP INSERTION/DELETION FUNCTIONS
/**
 * Inserts a capability into the first free slot in the bottle.
 * 
 * @param bottle The bottle to operate on.
 * @param cap    {The new cap.}_BRK (bound)
 * @param slot   Output: The slot into which cap was inserted.
 * @return       Error code.
 */
int32_t bottle_cap_add(bottle_t bottle, tpm_encrypted_cap_t* cap, uint32_t* slot);
/**
 * Deletes a capability from the specified slot. If the slot is empty,
 * this is a no-op.
 * 
 * @param bottle The bottle to operate on.
 * @param slot   The slot to clear.
 * @return       Error code.
 */
int32_t bottle_cap_delete(bottle_t bottle, uint32_t slot);

//INTER-BOTTLE CAP MIGRATION
/**
 * Exports a capability for migration to another bottle. (The remote
 * bottle uses bottle_cap_add to import it.)
 * 
 * @param bottle The bottle to operate on.
 * @param slot   The slot containing the cap to export.
 * @param rbrk   The public BRK for the bottle to export to.
 * @param move   Whether to delete the original cap.
 * @param cap    Output: {Exported cap}_rBRK (bound to BottleCap PCR values)
 * @return       Error code.
 */
int32_t bottle_cap_export(bottle_t bottle, uint32_t slot, tpm_rsakey_t* rbrk, bool move, tpm_encrypted_cap_t* cap);

//CAP INVOCATION FUNCTIONS
//TODO: Needham-Schroeder (ie Kerberos) protocol

#endif /* __BOTTLECAP_H__ */

