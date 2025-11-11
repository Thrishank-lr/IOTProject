/*
 * Copyright (c) 2024
 * Project configuration for RPL Replay Attack Demonstration
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Enable IPv6 */
#define UIP_CONF_IPV6 1

/* Use NullRDC for simplicity */
#define NETSTACK_CONF_RDC nullrdc_driver
#define NETSTACK_CONF_MAC csma_driver

/* Enable built-in RPL (rpl-lite) */
#ifndef NETSTACK_CONF_WITH_RPL
#define NETSTACK_CONF_WITH_RPL 1
#endif

/* Enable logging */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_6LOWPAN LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO

/* UDP buffer size */
#define UIP_CONF_UDP 1
#define UIP_CONF_UDP_CONNS 10

/* IPv6 buffer size */
#define UIP_CONF_BUFFER_SIZE 256

/* Enable simple UDP */
#define SIMPLE_UDP_CONF_MAX_PACKET_SIZE 128

#endif /* PROJECT_CONF_H_ */

