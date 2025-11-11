# RPL Replay Attack Demonstration

This example demonstrates a simplified RPL-like routing protocol with authentication to protect against replay attacks. It is a port of an ns-3 simulation to Contiki-NG.

## Overview

This demonstration includes:

1. **RPL Secure Node**: Implements a simplified RPL-like protocol with:
   - DIO (DODAG Information Object) message broadcasting
   - Nonce-based authentication challenge-response
   - Counter-based freshness checking
   - Parent selection based on rank
   - Replay attack protection through authentication

2. **Replay Attacker**: An attacker node that:
   - Listens for and captures DIO messages
   - Replays captured DIOs after a delay
   - Demonstrates how replay attacks can be detected and prevented

## File Structure

- `rpl-replay-demo.c` - Main file containing both RPL node and attacker code (like original ns-3)
- `rpl-replay-demo-node.c` - Wrapper to build RPL node executable
- `rpl-replay-demo-attacker.c` - Wrapper to build attacker executable
- `rpl-replay-demo.csc` - Cooja simulation configuration
- `project-conf.h` - Project configuration

## Building

### For Cooja Simulation

```bash
cd examples/rpl-replay-attack
make TARGET=cooja
```

This builds:
- `rpl-replay-demo-node.cooja` - For RPL nodes (root and regular nodes)
- `rpl-replay-demo-attacker.cooja` - For attacker node

### For Native (Linux)

```bash
make TARGET=native
sudo ./rpl-replay-demo-node.native
```

## Running in Cooja

1. **Start Cooja**:
   ```bash
   cd tools/cooja
   ./gradlew run
   ```

2. **Open Simulation**:
   - In Cooja: `File → Open simulation`
   - Navigate to `examples/rpl-replay-attack/rpl-replay-demo.csc`
   - Click `Open`

3. **Run Simulation**:
   - Click `Start` in the Simulation control panel
   - Watch the Mote output window for logs

## Simulation Setup

The simulation includes:
- **Node 1**: Root node (rank 0)
- **Node 2**: Regular node (connects to root)
- **Node 3**: Regular node (connects to root or node 2)
- **Node 4**: Regular node (connects to node 3)
- **Node 5**: Attacker node (captures and replays DIOs)

## Expected Behavior

### Normal Operation

1. Root node (ID 1) starts and broadcasts DIOs with rank 0
2. Regular nodes receive DIOs and initiate authentication
3. After successful authentication, nodes select parents and update ranks
4. Network forms a DODAG (Directed Acyclic Graph) with root at top

### Attack Scenario

1. Attacker node captures a DIO from the root
2. After delay (12 seconds), attacker replays the captured DIO
3. Legitimate nodes should:
   - **Detect replay** if counter is old (already seen)
   - **Require authentication** if sender is unknown
   - **Blacklist** if authentication fails or times out

## Protocol Details

### DIO Message Format

```
"sender_id version rank counter"
```

Example: `"1 1 0 5"` means sender ID 1, version 1, rank 0, counter 5

### Authentication Flow

1. Node receives DIO from unknown sender
2. Node sends `AUTH-REQ` with nonce
3. Sender responds with `AUTH-RESP` containing signed nonce
4. Node verifies signature and accepts sender
5. If authentication fails or times out, sender is blacklisted

### Authentication Messages

- **AUTH-REQ**: `"AUTH-REQ nonce"`
- **AUTH-RESP**: `"AUTH-RESP nonce signature"`

Signature: `nonce ^ SHARED_KEY` (XOR with shared key)

## Configuration

Key parameters in `rpl-replay-demo.c`:

- `DIO_PORT`: Port for DIO messages (30000)
- `DATA_PORT`: Port for data messages (40000)
- `SHARED_KEY`: Shared secret for authentication (0xA5A5A5A5)
- `AUTH_TIMEOUT`: Authentication timeout (2 seconds)
- `DIO_INTERVAL`: DIO broadcast interval (5 seconds)
- `RANK_INCREMENT`: Rank increase per hop (10)
- `REPLAY_DELAY`: Delay before first replay (12 seconds)
- `REPLAY_PERIOD`: Period between replays (10 seconds)

## How It Works

The single file (`rpl-replay-demo.c`) uses the `NODE_IS_ATTACKER` compile-time flag:

- **`NODE_IS_ATTACKER=0`** → Compiles as RPL node (legitimate nodes)
- **`NODE_IS_ATTACKER=1`** → Compiles as attacker node

The wrapper files set this flag automatically:
- `rpl-replay-demo-node.c` sets `NODE_IS_ATTACKER=0`
- `rpl-replay-demo-attacker.c` sets `NODE_IS_ATTACKER=1`

## Limitations

This is a **simplified demonstration** and has limitations:

1. **Not a full RPL implementation**: This is a simplified RPL-like protocol for demonstration
2. **Shared key**: Uses a simple shared key (in production, use proper key management)
3. **Node ID mapping**: Simplistic node ID to IPv6 address mapping
4. **No routing table**: Simplified parent selection without full routing table
5. **No packet forwarding**: Data forwarding is simplified

## Troubleshooting

### Nodes don't receive DIOs

- Check radio range in Cooja (should be 50.0)
- Check that nodes are within range
- Verify IPv6 addresses are assigned

### Authentication fails

- Check that shared key matches (0xA5A5A5A5)
- Verify nonce handling is correct
- Check timeout values

### Attacker not replaying

- Verify attacker captured a DIO (check logs)
- Check replay delay (12 seconds)
- Verify attacker is within radio range

## Comparison with ns-3 Version

This Contiki-NG version:

- Uses **IPv6** instead of IPv4
- Uses **simple_udp** instead of ns-3 Socket API
- Uses **PROCESS** instead of Application class
- Uses **etimer** instead of Simulator::Schedule
- Uses **event-driven** model instead of callback-based

The structure matches the original: one file with both node types, selected at compile time.

## References

- Contiki-NG RPL: `doc/programming/RPL.md`
- Contiki-NG UDP: `doc/programming/UDP-communication.md`
- Contiki-NG Security: `doc/programming/Communication-Security.md`

## License

See Contiki-NG license (3-clause BSD).
