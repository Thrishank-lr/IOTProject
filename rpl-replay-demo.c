/*
 * Copyright (c) 2024
 * Contiki-NG RPL Replay Attack Demonstration - Single File Version
 * 
 * This file contains both the RPL secure node and attacker functionality
 * in a single file, similar to the original ns-3 version.
 * 
 * Ported from ns-3 to Contiki-NG.
 */

 #include "contiki.h"
 #include "net/ipv6/simple-udp.h"
 #include "net/ipv6/uip.h"
 #include "net/ipv6/uip-ds6.h"
 #include "net/routing/routing.h"
 #include "sys/node-id.h"
 #include "sys/log.h"
 #include "lib/random.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <inttypes.h>
 
 #define LOG_MODULE "RplDemo"
 #define LOG_LEVEL LOG_LEVEL_INFO
 
 /* Ports */
 #define DIO_PORT 30000
 #define DATA_PORT 40000
 #define AUTH_PORT 30001
 
 /* Configuration: Set to 1 to run as attacker, 0 to run as RPL node */
 #ifndef NODE_IS_ATTACKER
 #define NODE_IS_ATTACKER 0
 #endif
 
 /* Authentication */
 #define SHARED_KEY 0xA5A5A5A5UL
 #define AUTH_TIMEOUT (10 * CLOCK_SECOND)
 #define DIO_INTERVAL (5 * CLOCK_SECOND)
 #define MAX_PENDING_AUTH 10
 
 /* RPL-like parameters */
 #define DEFAULT_RANK 1000000
 #define RANK_INCREMENT 10
 #define MAX_COUNTER_VALUE UINT32_MAX
 
 /* Attack parameters */
 #define REPLAY_DELAY (12 * CLOCK_SECOND)
 #define REPLAY_PERIOD (10 * CLOCK_SECOND)
 
 /* ============================================================================
  * RPL SECURE NODE FUNCTIONALITY
  * ============================================================================ */
 
 #if !NODE_IS_ATTACKER
 
 /* Node state */
 static uint32_t my_node_id;
 static uint32_t my_version = 1;
 static uint32_t my_rank = DEFAULT_RANK;
 static uint32_t my_counter = 0;
 static int my_parent_id = -1;
 static bool is_root = false;
 
 /* Authentication state */
 static uint32_t next_nonce = 1;
 
 struct pending_auth {
   uip_ipaddr_t src_addr;
   uint32_t sender_id;
   uint32_t version;
   uint32_t rank;
   uint32_t counter;
   uint32_t nonce;
   struct etimer timeout_timer;
   bool in_use;
 };
 
 static struct pending_auth pending_auths[MAX_PENDING_AUTH];
 static uint32_t last_seen_counter[256];
 static bool blacklisted[256];
 
 /* Parent address storage */
 static uip_ipaddr_t parent_addr;
 static bool has_parent_addr = false;
 
 /* UDP connections */
 static struct simple_udp_connection dio_conn;
 static struct simple_udp_connection data_conn;
 static struct simple_udp_connection auth_conn;
 
 /* Helper functions */
 static uint32_t sign_nonce(uint32_t nonce) {
   return nonce ^ SHARED_KEY;
 }
 
 static bool verify_nonce(uint32_t nonce, uint32_t sig) {
   return (sig == (nonce ^ SHARED_KEY));
 }
 
 static uint32_t extract_node_id_from_addr(const uip_ipaddr_t *addr) {
   return (addr->u8[14] << 8) | addr->u8[15];
 }
 
 static uint32_t get_sender_index(uint32_t sender_id) {
   return sender_id % 256;
 }
 
 static struct pending_auth* find_pending_auth(const uip_ipaddr_t *addr) {
   int i;
   for(i = 0; i < MAX_PENDING_AUTH; i++) {
     if(pending_auths[i].in_use && 
        uip_ipaddr_cmp(&pending_auths[i].src_addr, addr)) {
       return &pending_auths[i];
     }
   }
   return NULL;
 }
 
 static struct pending_auth* allocate_pending_auth(void) {
   int i;
   for(i = 0; i < MAX_PENDING_AUTH; i++) {
     if(!pending_auths[i].in_use) {
       pending_auths[i].in_use = true;
       return &pending_auths[i];
     }
   }
   return NULL;
 }
 
 static void free_pending_auth(struct pending_auth *pa) {
   if(pa) {
     etimer_stop(&pa->timeout_timer);
     pa->in_use = false;
   }
 }
 
 static void check_auth_timeouts(void) {
   int i;
   for(i = 0; i < MAX_PENDING_AUTH; i++) {
     if(pending_auths[i].in_use) {
       if(etimer_expired(&pending_auths[i].timeout_timer)) {
         uint32_t idx = get_sender_index(pending_auths[i].sender_id);
         LOG_INFO("AUTH timeout for sender %" PRIu32 ", blacklisting\n", 
                  pending_auths[i].sender_id);
         blacklisted[idx] = true;
         last_seen_counter[idx] = MAX_COUNTER_VALUE;
         free_pending_auth(&pending_auths[i]);
       }
     }
   }
 }
 
 static void send_auth_req(const uip_ipaddr_t *to, uint32_t nonce) {
   char msg[64];
   snprintf(msg, sizeof(msg), "AUTH-REQ %" PRIu32, nonce);
   simple_udp_sendto(&auth_conn, msg, strlen(msg), to);
   LOG_INFO("Sent AUTH-REQ to ");
   LOG_INFO_6ADDR(to);
   LOG_INFO_(" nonce=%" PRIu32 "\n", nonce);
 }
 
 static void send_auth_resp(const uip_ipaddr_t *to, uint32_t nonce) {
   char msg[64];
   uint32_t sig = sign_nonce(nonce);
   snprintf(msg, sizeof(msg), "AUTH-RESP %" PRIu32 " %" PRIu32, nonce, sig);
   simple_udp_sendto(&auth_conn, msg, strlen(msg), to);
   LOG_INFO("Sent AUTH-RESP to ");
   LOG_INFO_6ADDR(to);
   LOG_INFO_(" nonce=%" PRIu32 " sig=%" PRIu32 "\n", nonce, sig);
 }
 
 static void send_dio(void) {
   char payload[128];
   uip_ipaddr_t all_nodes;
   
   my_counter++;
   snprintf(payload, sizeof(payload), "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
            my_node_id, my_version, my_rank, my_counter);
   
   uip_create_linklocal_allnodes_mcast(&all_nodes);
   simple_udp_sendto(&dio_conn, payload, strlen(payload), &all_nodes);
   
   LOG_INFO("SENT DIO ver=%" PRIu32 " rank=%" PRIu32 " ctr=%" PRIu32 "\n",
            my_version, my_rank, my_counter);
 }
 
 static void handle_dio_recv(struct simple_udp_connection *c,
                             const uip_ipaddr_t *source_addr,
                             uint16_t source_port,
                             const uip_ipaddr_t *dest_addr,
                             uint16_t dest_port,
                             const uint8_t *data,
                             uint16_t datalen) {
   char payload[128];
   uint32_t sender_id, version, rank, counter;
   uint32_t idx;
   struct pending_auth *pa;
   
   if(datalen >= sizeof(payload)) datalen = sizeof(payload) - 1;
   memcpy(payload, data, datalen);
   payload[datalen] = '\0';
   
   if(sscanf(payload, "%" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32,
             &sender_id, &version, &rank, &counter) != 4) {
     return;
   }
   
   if(sender_id == my_node_id) return;
   
   idx = get_sender_index(sender_id);
   if(blacklisted[idx]) {
     LOG_INFO("IGNORE DIO from blacklisted sender %" PRIu32 "\n", sender_id);
     return;
   }
   
   if(last_seen_counter[idx] == 0 && !blacklisted[idx]) {
     pa = find_pending_auth(source_addr);
     if(pa) {
       pa->sender_id = sender_id;
       pa->version = version;
       pa->rank = rank;
       pa->counter = counter;
       return;
     }
     
     pa = allocate_pending_auth();
     if(!pa) return;
     
     uip_ipaddr_copy(&pa->src_addr, source_addr);
     pa->sender_id = sender_id;
     pa->version = version;
     pa->rank = rank;
     pa->counter = counter;
     pa->nonce = next_nonce++;
     etimer_set(&pa->timeout_timer, AUTH_TIMEOUT);
     send_auth_req(source_addr, pa->nonce);
     return;
   }
   
   if(counter < last_seen_counter[idx]) {
     LOG_INFO("IGNORE old DIO from %" PRIu32 " ctr=%" PRIu32 " (last=%" PRIu32 ")\n",
              sender_id, counter, last_seen_counter[idx]);
     return;
   }
   
   last_seen_counter[idx] = counter;
   
   if(!is_root) {
     uint32_t candidate_rank = rank + RANK_INCREMENT;
     if(candidate_rank < my_rank) {
       my_rank = candidate_rank;
       my_parent_id = (int)sender_id;
       uip_ipaddr_copy(&parent_addr, source_addr);
       has_parent_addr = true;
       LOG_INFO("SELECT parent %" PRIu32 " (new rank=%" PRIu32 ")\n",
                sender_id, my_rank);
     }
   }
 }
 
 static void handle_auth_recv(struct simple_udp_connection *c,
                              const uip_ipaddr_t *source_addr,
                              uint16_t source_port,
                              const uip_ipaddr_t *dest_addr,
                              uint16_t dest_port,
                              const uint8_t *data,
                              uint16_t datalen) {
   char payload[128];
   char tag[16];
   uint32_t nonce, sig;
   
   if(datalen >= sizeof(payload)) datalen = sizeof(payload) - 1;
   memcpy(payload, data, datalen);
   payload[datalen] = '\0';
   
   if(sscanf(payload, "%15s", tag) != 1) return;
   
   if(strcmp(tag, "AUTH-REQ") == 0) {
     if(sscanf(payload, "AUTH-REQ %" SCNu32, &nonce) == 1) {
       send_auth_resp(source_addr, nonce);
     }
   } else if(strcmp(tag, "AUTH-RESP") == 0) {
     LOG_INFO("AUTH handler received packet from ");
     LOG_INFO_6ADDR(source_addr);
     LOG_INFO_(" len=%d payload='%.*s'\n", datalen, datalen, (char*)data);
     if(sscanf(payload, "AUTH-RESP %" SCNu32 " %" SCNu32, &nonce, &sig) == 2) {
       struct pending_auth *pa = find_pending_auth(source_addr);
       if(pa && pa->nonce == nonce && verify_nonce(nonce, sig)) {
         uint32_t idx = get_sender_index(pa->sender_id);
         last_seen_counter[idx] = pa->counter;
         
         if(!is_root) {
           uint32_t candidate_rank = pa->rank + RANK_INCREMENT;
           if(candidate_rank < my_rank) {
             my_rank = candidate_rank;
             my_parent_id = (int)pa->sender_id;
             uip_ipaddr_copy(&parent_addr, source_addr);
             has_parent_addr = true;
             LOG_INFO("AUTH OK; SELECT parent %" PRIu32 " (new rank=%" PRIu32 ")\n",
                      pa->sender_id, my_rank);
           } else {
             LOG_INFO("AUTH OK; no parent change\n");
           }
         } else {
           LOG_INFO("AUTH OK from %" PRIu32 "\n", pa->sender_id);
         }
         free_pending_auth(pa);
       }
     }
   }
 }
 
 static void handle_data_recv(struct simple_udp_connection *c,
                              const uip_ipaddr_t *source_addr,
                              uint16_t source_port,
                              const uip_ipaddr_t *dest_addr,
                              uint16_t dest_port,
                              const uint8_t *data,
                              uint16_t datalen) {
   char payload[128];
   uint32_t src_id, dst_id;
   char msg[64];
   
   if(datalen >= sizeof(payload)) datalen = sizeof(payload) - 1;
   memcpy(payload, data, datalen);
   payload[datalen] = '\0';
   
   if(sscanf(payload, "%" SCNu32 " %" SCNu32 " %63s", &src_id, &dst_id, msg) != 3) {
     return;
   }
   
   if(is_root && dst_id == 0) {
     LOG_INFO("Root received DATA from %" PRIu32 ": %s\n", src_id, msg);
     return;
   }
   
   if(!is_root && my_parent_id >= 0 && has_parent_addr) {
     simple_udp_sendto(&data_conn, payload, strlen(payload), &parent_addr);
     LOG_INFO("FORWARD data from %" PRIu32 " to parent %d\n", src_id, my_parent_id);
   }
 }
 
 PROCESS(rpl_secure_node_process, "RPL Secure Node");
 AUTOSTART_PROCESSES(&rpl_secure_node_process);
 
 PROCESS_THREAD(rpl_secure_node_process, ev, data) {
   static struct etimer dio_timer;
   
   PROCESS_BEGIN();
   
   my_node_id = node_id;
   if(my_node_id == 0) {
     uip_ds6_addr_t *addr = uip_ds6_get_global(ADDR_PREFERRED);
     if(addr) {
       my_node_id = extract_node_id_from_addr(&addr->ipaddr);
     }
     if(my_node_id == 0) {
       my_node_id = 1;
     }
   }
   
   is_root = (my_node_id == 1);
   if(is_root) {
     my_rank = 0;
     LOG_INFO("Starting as ROOT node (ID %" PRIu32 ")\n", my_node_id);
     /* Start built-in RPL root to form the DODAG */
     NETSTACK_ROUTING.root_start();
   } else {
     my_rank = DEFAULT_RANK;
     LOG_INFO("Starting as node ID %" PRIu32 " (rank %" PRIu32 ")\n", my_node_id, my_rank);
   }
   
   memset(last_seen_counter, 0, sizeof(last_seen_counter));
   memset(blacklisted, 0, sizeof(blacklisted));
   memset(pending_auths, 0, sizeof(pending_auths));
   
   /* Register UDP sockets: 
    * - dio_conn/auth_conn manage our mitigation control plane
    * - data_conn will be used to generate periodic app traffic over RPL
    */
   simple_udp_register(&dio_conn, DIO_PORT, NULL, DIO_PORT, handle_dio_recv);
   simple_udp_register(&data_conn, DATA_PORT, NULL, DATA_PORT, handle_data_recv);
   simple_udp_register(&auth_conn, AUTH_PORT, NULL, AUTH_PORT, handle_auth_recv);
   
   etimer_set(&dio_timer, CLOCK_SECOND + (random_rand() % CLOCK_SECOND));
   
   /* Also generate periodic UDP app traffic to the root so you can 
    * see packets in Timeline/Mote output routed by built-in RPL.
    */
   static struct etimer app_timer;
   etimer_set(&app_timer, 5 * CLOCK_SECOND);
   
   while(1) {
     PROCESS_WAIT_EVENT();
     check_auth_timeouts();
     if(etimer_expired(&dio_timer)) {
       send_dio();
       etimer_set(&dio_timer, DIO_INTERVAL + (random_rand() % CLOCK_SECOND));
     }
     if(etimer_expired(&app_timer)) {
       /* If we can reach the root, send a small UDP message */
       uip_ipaddr_t root_ip;
       if(NETSTACK_ROUTING.node_is_reachable() &&
          NETSTACK_ROUTING.get_root_ipaddr(&root_ip)) {
         const char *msg = "hello-rpl";
         simple_udp_sendto(&data_conn, msg, strlen(msg), &root_ip);
         LOG_INFO("App sent UDP to root over RPL\n");
       } else {
         LOG_INFO("App: root not reachable yet\n");
       }
       etimer_set(&app_timer, 10 * CLOCK_SECOND);
     }
   }
   
   PROCESS_END();
 }
 
 /* ============================================================================
  * ATTACKER NODE FUNCTIONALITY
  * ============================================================================ */
 
 #else /* NODE_IS_ATTACKER */
 
 static char captured_payload[256];
 static bool has_captured = false;
 static struct etimer replay_timer;
 static struct simple_udp_connection dio_conn;
 
 static void replay_captured(void) {
   uip_ipaddr_t all_nodes;
   
   if(!has_captured || captured_payload[0] == '\0') {
     return;
   }
   
   uip_create_linklocal_allnodes_mcast(&all_nodes);
   simple_udp_sendto(&dio_conn, captured_payload, strlen(captured_payload), &all_nodes);
   
   LOG_INFO("Attacker REPLAYED captured DIO: %s\n", captured_payload);
   etimer_set(&replay_timer, REPLAY_PERIOD);
 }
 
 static void handle_dio_sniff(struct simple_udp_connection *c,
                              const uip_ipaddr_t *source_addr,
                              uint16_t source_port,
                              const uip_ipaddr_t *dest_addr,
                              uint16_t dest_port,
                              const uint8_t *data,
                              uint16_t datalen) {
   if(!has_captured && datalen > 0) {
     size_t len = datalen;
     if(len >= sizeof(captured_payload)) len = sizeof(captured_payload) - 1;
     
     memcpy(captured_payload, data, len);
     captured_payload[len] = '\0';
     has_captured = true;
     
     LOG_INFO("Attacker CAPTURED DIO payload: %s\n", captured_payload);
     LOG_INFO("  From ");
     LOG_INFO_6ADDR(source_addr);
     LOG_INFO_("\n");
     
     etimer_set(&replay_timer, REPLAY_DELAY);
   }
 }
 
 PROCESS(rpl_attacker_process, "RPL Attacker");
 AUTOSTART_PROCESSES(&rpl_attacker_process);
 
 PROCESS_THREAD(rpl_attacker_process, ev, data) {
   PROCESS_BEGIN();
   
   LOG_INFO("Attacker started; will replay after %lu seconds once captured\n",
            (unsigned long)(REPLAY_DELAY / CLOCK_SECOND));
   
   simple_udp_register(&dio_conn, DIO_PORT, NULL, DIO_PORT, handle_dio_sniff);
   
   captured_payload[0] = '\0';
   has_captured = false;
   
   while(1) {
     PROCESS_WAIT_EVENT();
     if(etimer_expired(&replay_timer)) {
       replay_captured();
     }
   }
   
   PROCESS_END();
 }
 
 #endif /* NODE_IS_ATTACKER */