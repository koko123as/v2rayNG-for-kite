package com.v2ray.ang.contracts

import libv2ray.TunConfig

/**
 * Implemented by the VPN service: establishes the VpnService interface sing-box asks for when its
 * tun inbound starts, and returns the descriptor. The service keeps ownership of the descriptor.
 */
interface TunOpener {
    @Throws(Exception::class)
    fun openTun(config: TunConfig): Int
}
