#ifndef CSIMRS_SHIM_H
#define CSIMRS_SHIM_H

#include <stdint.h>
#include <stddef.h>

void simrs_init(const uint8_t *ki, const uint8_t *k, const uint8_t *opc);
uint32_t simrs_init_profile(const uint8_t *der_ptr, uint32_t der_len);
uint32_t simrs_reset(uint8_t *atr_buf, uint32_t atr_buf_len);
uint32_t simrs_apdu(const uint8_t *cmd, uint32_t cmd_len, uint8_t *rsp_buf, uint32_t rsp_buf_len);
uint32_t simrs_snapshot_save(uint8_t *buf, uint32_t buf_len);
uint32_t simrs_snapshot_restore(const uint8_t *buf, uint32_t buf_len);
uint32_t simrs_snapshot_size(void);
uint64_t simrs_state_hash(void);

#endif
