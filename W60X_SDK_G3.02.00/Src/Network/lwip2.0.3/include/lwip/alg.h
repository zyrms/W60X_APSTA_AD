/******************************************************************************

  Copyright (C) 2015 Winner Micro electronics Co., Ltd.

 ******************************************************************************
  File Name     : alg.h
  Version       : Initial Draft
  Author        : Li Limin, lilm@winnermicro.com
  Created       : 2015/3/7
  Last Modified :
  Description   : Application layer gateway, (alg) only for apsta

  History       :
  Date          : 2015/3/7
  Author        : Li Limin, lilm@winnermicro.com
  Modification  : Created file

******************************************************************************/
#ifndef __ALG_H__
#define __ALG_H__


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


/* ============================== configure ===================== */
/* napt age time (second) */
#define NAPT_TABLE_TIMEOUT           60

/* napt port range: 15000~25000 */
#define NAPT_LOCAL_PORT_RANGE_START  0x3A98
#define NAPT_LOCAL_PORT_RANGE_END    0x61A8

/* napt icmp id range: 3000-65535 */
#define NAPT_ICMP_ID_RANGE_START     0xBB8
#define NAPT_ICMP_ID_RANGE_END       0xFFFF


/* napt table size */
//#define NAPT_TABLE_LIMIT
#ifdef  NAPT_TABLE_LIMIT
#define NAPT_TABLE_SIZE_MAX          3000
#endif

#define NAPT_USE_HOOK                 1
/* ============================================================ */


#define NAPT_TMR_INTERVAL            ((NAPT_TABLE_TIMEOUT / 2) * 1000UL)

extern bool alg_napt_port_is_used(u16 port);

extern int alg_napt_init(void);

extern int alg_input(const u8 *bssid, u8 *pkt_body, u32 pkt_len);


#if NAPT_USE_HOOK
typedef enum alg_hook_type {
    ALG_HOOK_TYPE_TCP = 0,
    ALG_HOOK_TYPE_UDP
} alg_hook_type_e;

typedef enum alg_hook_action {
    ALG_HOOK_ACTION_NORMAL = 0,
    ALG_HOOK_ACTION_DROP
} alg_hook_action_e;

typedef alg_hook_action_e (*alg_hook_callback)(u8 *ehdr, u16 eth_len);

extern void alg_set_input_hook(alg_hook_type_e type, alg_hook_callback input);

extern void alg_set_output_hook(alg_hook_type_e type, alg_hook_callback output);
#endif /* NAPT_USE_HOOK */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __ALG_H__ */

