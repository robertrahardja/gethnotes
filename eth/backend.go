// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
// This is the CORE of the Ethereum node - it ties together all the major components
package eth

import (
	// Standard Go libraries
	"context"       // For context-aware operations
	"encoding/json" // For JSON configuration parsing
	"fmt"           // For formatting strings and errors
	"math"          // Math operations
	"math/big"      // For handling Ethereum's 256-bit integers
	"runtime"       // To get Go runtime info for version reporting
	"sync"          // For thread-safe operations (mutexes)
	"time"          // For time-based operations

	// Ethereum account management
	"github.com/ethereum/go-ethereum/accounts" // Manages user accounts and wallets
	"github.com/ethereum/go-ethereum/common"   // Common types like addresses and hashes
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus" // Consensus engines (PoS, PoA, etc)
	
	// Core blockchain components
	"github.com/ethereum/go-ethereum/core"              // Core blockchain logic
	"github.com/ethereum/go-ethereum/core/filtermaps"   // Event log filtering
	"github.com/ethereum/go-ethereum/core/rawdb"        // Low-level database operations
	"github.com/ethereum/go-ethereum/core/state/pruner" // State pruning utilities
	"github.com/ethereum/go-ethereum/core/txpool"       // Transaction pool management
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"    // EIP-4844 blob transactions
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"  // Regular transactions
	"github.com/ethereum/go-ethereum/core/txpool/locals"      // Local transaction tracking
	"github.com/ethereum/go-ethereum/core/types"              // Blockchain data types
	"github.com/ethereum/go-ethereum/core/vm"                 // Ethereum Virtual Machine
	
	// Ethereum-specific components
	"github.com/ethereum/go-ethereum/eth/downloader"       // Blockchain sync logic
	"github.com/ethereum/go-ethereum/eth/ethconfig"        // Ethereum configuration
	"github.com/ethereum/go-ethereum/eth/gasprice"         // Gas price oracle
	"github.com/ethereum/go-ethereum/eth/protocols/eth"    // ETH wire protocol
	"github.com/ethereum/go-ethereum/eth/protocols/snap"   // Snapshot protocol for fast sync
	"github.com/ethereum/go-ethereum/eth/tracers"          // Transaction tracing
	
	// Infrastructure components
	"github.com/ethereum/go-ethereum/ethdb"                   // Database interface
	"github.com/ethereum/go-ethereum/event"                   // Event system
	"github.com/ethereum/go-ethereum/internal/ethapi"         // Internal RPC APIs
	"github.com/ethereum/go-ethereum/internal/shutdowncheck"  // Graceful shutdown tracking
	"github.com/ethereum/go-ethereum/internal/version"        // Version info
	"github.com/ethereum/go-ethereum/log"                     // Logging
	"github.com/ethereum/go-ethereum/miner"                   // Block production
	"github.com/ethereum/go-ethereum/node"                    // Node infrastructure
	"github.com/ethereum/go-ethereum/p2p"                     // P2P networking
	"github.com/ethereum/go-ethereum/p2p/dnsdisc"            // DNS-based discovery
	"github.com/ethereum/go-ethereum/p2p/enode"              // Ethereum Node Records
	"github.com/ethereum/go-ethereum/params"                  // Protocol parameters
	"github.com/ethereum/go-ethereum/rlp"                     // RLP encoding
	"github.com/ethereum/go-ethereum/rpc"                     // RPC server
	gethversion "github.com/ethereum/go-ethereum/version"     // Geth version info
)

const (
	// discmixTimeout controls how long we wait for each peer discovery source
	// This prevents slow sources from blocking faster ones
	// Example: DNS might be slow, but we don't want to wait forever - we'll try DHT too
	discmixTimeout = 100 * time.Millisecond

	// discoveryPrefetchBuffer is how many potential peers to keep ready
	// This ensures we always have peers to try connecting to, even if discovery is slow
	discoveryPrefetchBuffer = 32

	// maxParallelENRRequests limits concurrent ENR (Ethereum Node Record) lookups
	// This prevents overwhelming the network with too many requests at once
	maxParallelENRRequests = 16
)

// Config is an alias for ethconfig.Config for backward compatibility
// Deprecated: use ethconfig.Config directly instead
type Config = ethconfig.Config

// Ethereum implements the Ethereum full node service.
// This is the main struct that ties together ALL components of an Ethereum node
type Ethereum struct {
	// Core protocol objects - these are the heart of Ethereum
	config         *ethconfig.Config   // All configuration settings
	txPool         *txpool.TxPool      // Pending transactions waiting to be mined
	blobTxPool     *blobpool.BlobPool  // EIP-4844 blob transactions (for rollup data)
	localTxTracker *locals.TxTracker   // Tracks transactions from local accounts
	blockchain     *core.BlockChain    // The actual blockchain (all blocks and state)

	// Network components - handle peer-to-peer communication
	handler *handler        // Processes incoming network messages
	discmix *enode.FairMix  // Mixes different peer discovery sources fairly
	dropper *dropper        // Manages dropping bad or excess peers

	// Database - where everything is stored
	chainDb ethdb.Database // Stores blocks, transactions, and state

	// Event system - allows components to communicate
	eventMux *event.TypeMux // Central event bus for internal notifications
	
	// Consensus - how blocks are validated
	engine consensus.Engine // Proof-of-Stake, Proof-of-Authority, etc.
	
	// Account management
	accountManager *accounts.Manager // Manages user wallets and accounts

	// Event filtering - for dapp subscriptions
	filterMaps      *filtermaps.FilterMaps // Indexes logs for quick filtering
	closeFilterMaps chan chan struct{}     // Channel to signal filterMaps shutdown

	// API backend - serves JSON-RPC requests
	APIBackend *EthAPIBackend // Handles all RPC API calls

	// Mining/Validation
	miner    *miner.Miner // Creates new blocks (if validator)
	gasPrice *big.Int     // Minimum gas price for transactions

	// Network identity
	networkID     uint64           // Which Ethereum network (1=mainnet, etc.)
	netRPCService *ethapi.NetAPI   // Network-related RPC APIs

	// P2P server
	p2pServer *p2p.Server // The underlying P2P networking server

	// Thread safety
	lock sync.RWMutex // Protects concurrent access to changing fields

	// Shutdown tracking
	shutdownTracker *shutdowncheck.ShutdownTracker // Detects unclean shutdowns
}

// New creates a new Ethereum object (including the initialisation of the common Ethereum object),
// whose lifecycle will be managed by the provided node.
// This is THE function that creates the entire Ethereum service when geth starts
func New(stack *node.Node, config *ethconfig.Config) (*Ethereum, error) {
	// First, validate the configuration to catch problems early
	
	// Check sync mode is valid (full, snap, or light)
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	
	// Check history mode is valid (archive, full, or light)
	if !config.HistoryMode.IsValid() {
		return nil, fmt.Errorf("invalid history mode %d", config.HistoryMode)
	}
	
	// Ensure miner has a valid gas price (even if not mining)
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Sign() <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", ethconfig.Defaults.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(ethconfig.Defaults.Miner.GasPrice)
	}
	// Memory allocation optimization for archive nodes
	// Archive nodes don't need dirty cache since they never prune
	if config.NoPruning && config.TrieDirtyCache > 0 && config.StateScheme == rawdb.HashScheme {
		if config.SnapshotCache > 0 {
			// Split the dirty cache between clean cache (60%) and snapshots (40%)
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			// No snapshots, give all dirty cache to clean cache
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	// Log how much memory we're using for caches
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	// Set up database configuration
	dbOptions := node.DatabaseOptions{
		Cache:             config.DatabaseCache,      // Memory for database cache (MB)
		Handles:           config.DatabaseHandles,    // Number of open file descriptors
		AncientsDirectory: config.DatabaseFreezer,    // Where to store old chain data
		EraDirectory:      config.DatabaseEra,        // Where to store Era archives
		MetricsNamespace:  "eth/db/chaindata/",      // Prometheus metrics prefix
	}
	
	// Open the main blockchain database
	chainDb, err := stack.OpenDatabaseWithOptions("chaindata", dbOptions)
	if err != nil {
		return nil, err
	}
	// Determine how we store state (hash-based or path-based)
	scheme, err := rawdb.ParseStateScheme(config.StateScheme, chainDb)
	if err != nil {
		return nil, err
	}
	
	// Check if state pruning was interrupted (only for hash scheme)
	// This can happen if geth was killed during pruning
	if scheme == rawdb.HashScheme {
		if err := pruner.RecoverPruning(stack.ResolvePath(""), chainDb); err != nil {
			log.Error("Failed to recover state", "error", err)
		}
	}

	// Load blockchain configuration and genesis state
	// This tells us which network we're on (mainnet, testnet, etc.)
	chainConfig, _, err := core.LoadChainConfig(chainDb, config.Genesis)
	if err != nil {
		return nil, err
	}
	
	// Create the consensus engine (Proof-of-Stake, etc.)
	engine, err := ethconfig.CreateConsensusEngine(chainConfig, chainDb)
	if err != nil {
		return nil, err
	}
	
	// Network ID identifies which Ethereum network we're on
	// If not specified, use the chain ID from genesis
	networkID := config.NetworkId
	if networkID == 0 {
		networkID = chainConfig.ChainID.Uint64()
	}

	// Create the main Ethereum service object
	// This brings together all the components we'll need
	eth := &Ethereum{
		config:          config,                                      // Configuration
		chainDb:         chainDb,                                     // Database handle
		eventMux:        stack.EventMux(),                           // Event system from node
		accountManager:  stack.AccountManager(),                     // Wallet management from node
		engine:          engine,                                      // Consensus algorithm
		networkID:       networkID,                                   // Which network we're on
		gasPrice:        config.Miner.GasPrice,                      // Minimum gas price
		p2pServer:       stack.Server(),                             // P2P networking from node
		discmix:         enode.NewFairMix(discmixTimeout),           // Fair peer discovery mixer
		shutdownTracker: shutdowncheck.NewShutdownTracker(chainDb),  // Tracks clean shutdowns
	}
	// Check database version for compatibility
	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "network", networkID, "dbversion", dbVer)

	// Verify database version compatibility
	// This prevents using an incompatible database format
	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			// Database is newer than this geth version - can't use it
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, version.WithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			// Database is older or new - upgrade it
			if bcVersion != nil { // only print warning on upgrade, not on init
				log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	// Configure the blockchain with all our settings
	var (
		options = &core.BlockChainConfig{
			// Memory cache settings
			TrieCleanLimit:   config.TrieCleanCache,     // Clean trie cache size (MB)
			TrieDirtyLimit:   config.TrieDirtyCache,     // Dirty trie cache size (MB)
			SnapshotLimit:    config.SnapshotCache,      // Snapshot cache size (MB)
			
			// Performance settings
			NoPrefetch:       config.NoPrefetch,         // Disable state prefetching
			TrieTimeLimit:    config.TrieTimeout,        // Time limit for trie operations
			
			// Storage settings
			ArchiveMode:      config.NoPruning,          // Keep all historical state?
			Preimages:        config.Preimages,          // Store trie key preimages?
			StateHistory:     config.StateHistory,       // How many recent states to keep
			StateScheme:      scheme,                    // Hash or path-based storage
			ChainHistoryMode: config.HistoryMode,        // Full or light history
			TxLookupLimit:    int64(min(config.TransactionHistory, math.MaxInt64)),
			
			// EVM configuration
			VmConfig: vm.Config{
				EnablePreimageRecording: config.EnablePreimageRecording,
			},
			
			// Trie journaling (for crash recovery)
			// Stores trie updates to disk for faster restarts
			TrieJournalDirectory: stack.ResolvePath("triedb"),
		}
	)
	// Set up EVM tracing if requested (for debugging)
	if config.VMTrace != "" {
		// Default to empty config
		traceConfig := json.RawMessage("{}")
		if config.VMTraceJsonConfig != "" {
			// Use provided config
			traceConfig = json.RawMessage(config.VMTraceJsonConfig)
		}
		// Create the tracer
		t, err := tracers.LiveDirectory.New(config.VMTrace, traceConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create tracer %s: %v", config.VMTrace, err)
		}
		options.VmConfig.Tracer = t
	}
	// Allow overriding hardfork activation times (for testing)
	var overrides core.ChainOverrides
	if config.OverrideOsaka != nil {
		overrides.OverrideOsaka = config.OverrideOsaka
	}
	if config.OverrideVerkle != nil {
		overrides.OverrideVerkle = config.OverrideVerkle
	}
	options.Overrides = &overrides

	// Create the blockchain itself!
	// This is where all blocks and state are managed
	eth.blockchain, err = core.NewBlockChain(chainDb, config.Genesis, eth.engine, options)
	if err != nil {
		return nil, err
	}

	// Set up filter maps for efficient log searching
	// This allows dapps to quickly find events they're interested in
	fmConfig := filtermaps.Config{
		History:        config.LogHistory,            // How many blocks of logs to index
		Disabled:       config.LogNoHistory,          // Disable log indexing?
		ExportFileName: config.LogExportCheckpoints,  // Export checkpoints file
		HashScheme:     scheme == rawdb.HashScheme,   // Using hash-based storage?
	}
	
	// Create a view of the current chain state
	chainView := eth.newChainView(eth.blockchain.CurrentBlock())
	historyCutoff, _ := eth.blockchain.HistoryPruningCutoff()
	
	// Get the finalized block number (for Proof-of-Stake)
	var finalBlock uint64
	if fb := eth.blockchain.CurrentFinalBlock(); fb != nil {
		finalBlock = fb.Number.Uint64()
	}
	
	// Create the filter maps
	filterMaps, err := filtermaps.NewFilterMaps(chainDb, chainView, historyCutoff, finalBlock, filtermaps.DefaultParams, fmConfig)
	if err != nil {
		return nil, err
	}
	eth.filterMaps = filterMaps
	eth.closeFilterMaps = make(chan chan struct{})  // Channel for clean shutdown

	// Set up transaction pools (where pending transactions wait)
	
	// Legacy transaction pool journal path (for saving local txs)
	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	// Create legacy transaction pool (regular transactions)
	legacyPool := legacypool.New(config.TxPool, eth.blockchain)

	// Blob transaction pool path (for EIP-4844 rollup data)
	if config.BlobPool.Datadir != "" {
		config.BlobPool.Datadir = stack.ResolvePath(config.BlobPool.Datadir)
	}
	// Create blob transaction pool
	eth.blobTxPool = blobpool.New(config.BlobPool, eth.blockchain, legacyPool.HasPendingAuth)

	// Combine both pools into one transaction pool
	eth.txPool, err = txpool.New(config.TxPool.PriceLimit, eth.blockchain, []txpool.SubPool{legacyPool, eth.blobTxPool})
	if err != nil {
		return nil, err
	}

	// Set up local transaction tracking
	// This ensures transactions from local accounts survive restarts
	if !config.TxPool.NoLocals {
		// Ensure journal time is reasonable (at least 1 second)
		rejournal := config.TxPool.Rejournal
		if rejournal < time.Second {
			log.Warn("Sanitizing invalid txpool journal time", "provided", rejournal, "updated", time.Second)
			rejournal = time.Second
		}
		// Create the local transaction tracker
		eth.localTxTracker = locals.New(config.TxPool.Journal, rejournal, eth.blockchain.Config(), eth.txPool)
		stack.RegisterLifecycle(eth.localTxTracker)
	}

	// Calculate total cache for the downloader to use during sync
	cacheLimit := options.TrieCleanLimit + options.TrieDirtyLimit + options.SnapshotLimit
	
	// Create the protocol handler (manages all network communication)
	if eth.handler, err = newHandler(&handlerConfig{
		NodeID:         eth.p2pServer.Self().ID(),    // Our node's unique ID
		Database:       chainDb,                       // Database for storing data
		Chain:          eth.blockchain,                // The blockchain to sync
		TxPool:         eth.txPool,                    // Transaction pool to broadcast
		Network:        networkID,                     // Which network we're on
		Sync:           config.SyncMode,               // How to sync (full/snap)
		BloomCache:     uint64(cacheLimit),            // Memory for bloom filters
		EventMux:       eth.eventMux,                  // Event system
		RequiredBlocks: config.RequiredBlocks,         // Blocks we must have
	}); err != nil {
		return nil, err
	}

	// Create the peer dropper (manages disconnecting bad/excess peers)
	eth.dropper = newDropper(eth.p2pServer.MaxDialedConns(), eth.p2pServer.MaxInboundConns())

	// Create the miner (even if not mining, needed for APIs)
	eth.miner = miner.New(eth, config.Miner, eth.engine)
	// Set extra data to include in mined blocks
	eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))
	// Set addresses that get priority in block inclusion
	eth.miner.SetPrioAddresses(config.TxPool.Locals)

	// Create the API backend (handles JSON-RPC requests)
	eth.APIBackend = &EthAPIBackend{
		stack.Config().ExtRPCEnabled(),      // Allow external RPC?
		stack.Config().AllowUnprotectedTxs,  // Allow non-EIP155 txs?
		eth,                                 // Reference to Ethereum service
		nil,                                 // Gas price oracle (set below)
	}
	if eth.APIBackend.allowUnprotectedTxs {
		log.Info("Unprotected transactions allowed")
	}
	// Create gas price oracle (suggests gas prices for transactions)
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, config.GPO, config.Miner.GasPrice)

	// Create network RPC service (net_ namespace APIs)
	eth.netRPCService = ethapi.NewNetAPI(eth.p2pServer, networkID)

	// Register everything with the node
	stack.RegisterAPIs(eth.APIs())           // Register RPC APIs
	stack.RegisterProtocols(eth.Protocols()) // Register P2P protocols
	stack.RegisterLifecycle(eth)             // Register start/stop hooks

	// Mark successful startup and check for previous crashes
	eth.shutdownTracker.MarkStartup()

	// All done! Return the fully constructed Ethereum service
	return eth, nil
}

// makeExtraData creates the extra data field for mined blocks
// This appears in every block this node mines, like a signature
func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// Create default extra data with version info
		// Format: [version, "geth", go version, OS]
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(gethversion.Major<<16 | gethversion.Minor<<8 | gethversion.Patch),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	// Ensure extra data isn't too large (max 32 bytes)
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// APIs return the collection of RPC services the ethereum package offers.
// These are the APIs that external applications can call
func (s *Ethereum) APIs() []rpc.API {
	// Get standard APIs (eth_, web3_, etc.)
	apis := ethapi.GetAPIs(s.APIBackend)

	// Add Ethereum-specific APIs
	return append(apis, []rpc.API{
		{
			Namespace: "miner",
			Service:   NewMinerAPI(s),  // Mining/validation APIs
		}, {
			Namespace: "eth",
			Service:   downloader.NewDownloaderAPI(s.handler.downloader, s.blockchain, s.eventMux),  // Sync status
		}, {
			Namespace: "admin",
			Service:   NewAdminAPI(s),  // Node administration
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(s),  // Debugging tools
		}, {
			Namespace: "net",
			Service:   s.netRPCService,  // Network info
		},
	}...)
}

// ResetWithGenesisBlock resets the blockchain to a new genesis block
// Used mainly for testing to start with a clean chain
func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

// Getter methods to access Ethereum components
// These allow other packages to interact with the Ethereum service

func (s *Ethereum) Miner() *miner.Miner { return s.miner }  // Block producer

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }  // Wallet manager
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }      // The blockchain
func (s *Ethereum) TxPool() *txpool.TxPool             { return s.txPool }          // Transaction pool
func (s *Ethereum) BlobTxPool() *blobpool.BlobPool     { return s.blobTxPool }      // Blob transaction pool
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }          // Consensus engine
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }         // Database
func (s *Ethereum) IsListening() bool                  { return true }              // Always listening for peers
func (s *Ethereum) Downloader() *downloader.Downloader { return s.handler.downloader }  // Sync manager
func (s *Ethereum) Synced() bool                       { return s.handler.synced.Load() }  // Are we synced?
func (s *Ethereum) SetSynced()                         { s.handler.enableSyncedFeatures() }  // Mark as synced
func (s *Ethereum) ArchiveMode() bool                  { return s.config.NoPruning }  // Full history mode?

// Protocols returns all the currently configured network protocols to start.
// These define how this node communicates with other Ethereum nodes
func (s *Ethereum) Protocols() []p2p.Protocol {
	// Always include ETH protocol (for blocks and transactions)
	protos := eth.MakeProtocols((*ethHandler)(s.handler), s.networkID, s.discmix)
	
	// Add SNAP protocol if we have snapshot cache (for fast sync)
	if s.config.SnapshotCache > 0 {
		protos = append(protos, snap.MakeProtocols((*snapHandler)(s.handler))...)
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
// This is called when the node starts up
func (s *Ethereum) Start() error {
	// Set up peer discovery sources (DNS, DHT, etc.)
	if err := s.setupDiscovery(); err != nil {
		return err
	}

	// Start tracking shutdowns (to detect crashes)
	s.shutdownTracker.Start()

	// Start the network protocol handler
	s.handler.Start(s.p2pServer.MaxPeers)

	// Start peer connection management
	// Drop peers more aggressively while syncing
	s.dropper.Start(s.p2pServer, func() bool { return !s.Synced() })

	// Start log indexing for event filters
	s.filterMaps.Start()
	go s.updateFilterMapsHeads()  // Keep filter maps updated with new blocks
	return nil
}

// newChainView creates a view of the blockchain at a specific block
// Used by filter maps to index logs efficiently
func (s *Ethereum) newChainView(head *types.Header) *filtermaps.ChainView {
	if head == nil {
		return nil
	}
	return filtermaps.NewChainView(s.blockchain, head.Number.Uint64(), head.Hash())
}

// updateFilterMapsHeads keeps the filter maps updated as new blocks arrive
// This runs in a goroutine for the lifetime of the node
func (s *Ethereum) updateFilterMapsHeads() {
	// Subscribe to blockchain events
	headEventCh := make(chan core.ChainEvent, 10)        // New blocks
	blockProcCh := make(chan bool, 10)                   // Block processing status
	sub := s.blockchain.SubscribeChainEvent(headEventCh)
	sub2 := s.blockchain.SubscribeBlockProcessingEvent(blockProcCh)
	
	// Clean up on exit
	defer func() {
		sub.Unsubscribe()
		sub2.Unsubscribe()
		// Drain channels to avoid goroutine leaks
		for {
			select {
			case <-headEventCh:
			case <-blockProcCh:
			default:
				return
			}
		}
	}()

	// Track the current head block
	var head *types.Header
	
	// Helper function to update filter maps when head changes
	setHead := func(newHead *types.Header) {
		if newHead == nil {
			return
		}
		// Only update if the head actually changed
		if head == nil || newHead.Hash() != head.Hash() {
			head = newHead
			// Create new chain view at this head
			chainView := s.newChainView(head)
			// Get history pruning info
			historyCutoff, _ := s.blockchain.HistoryPruningCutoff()
			// Get finalized block (for Proof-of-Stake)
			var finalBlock uint64
			if fb := s.blockchain.CurrentFinalBlock(); fb != nil {
				finalBlock = fb.Number.Uint64()
			}
			// Update filter maps target
			s.filterMaps.SetTarget(chainView, historyCutoff, finalBlock)
		}
	}
	
	// Initialize with current block
	setHead(s.blockchain.CurrentBlock())

	// Main event loop
	for {
		select {
		case ev := <-headEventCh:
			// New block arrived - update filter maps
			setHead(ev.Header)
			
		case blockProc := <-blockProcCh:
			// Block processing status changed
			s.filterMaps.SetBlockProcessing(blockProc)
			
		case <-time.After(time.Second * 10):
			// Periodic refresh in case we missed an event
			setHead(s.blockchain.CurrentBlock())
			
		case ch := <-s.closeFilterMaps:
			// Shutdown requested
			close(ch)
			return
		}
	}
}

// setupDiscovery configures peer discovery mechanisms
// This is how we find other Ethereum nodes to connect to
func (s *Ethereum) setupDiscovery() error {
	// Start updating our ENR (Ethereum Node Record) with chain info
	// This tells other nodes what we support
	eth.StartENRUpdater(s.blockchain, s.p2pServer.LocalNode())

	// Set up DNS-based discovery
	dnsclient := dnsdisc.NewClient(dnsdisc.Config{})
	
	// Add ETH protocol nodes from DNS
	if len(s.config.EthDiscoveryURLs) > 0 {
		iter, err := dnsclient.NewIterator(s.config.EthDiscoveryURLs...)
		if err != nil {
			return err
		}
		s.discmix.AddSource(iter)
	}

	// Add SNAP protocol nodes from DNS
	// These help with fast sync
	if len(s.config.SnapDiscoveryURLs) > 0 {
		iter, err := dnsclient.NewIterator(s.config.SnapDiscoveryURLs...)
		if err != nil {
			return err
		}
		s.discmix.AddSource(iter)
	}

	// Add nodes from Discovery v4 (Kademlia-like DHT)
	if s.p2pServer.DiscoveryV4() != nil {
		// Get random nodes from the DHT
		iter := s.p2pServer.DiscoveryV4().RandomNodes()
		
		// Function to resolve full node records
		resolverFunc := func(ctx context.Context, enr *enode.Node) *enode.Node {
			// Try to get the full ENR (with capabilities info)
			nn, _ := s.p2pServer.DiscoveryV4().RequestENR(enr)
			return nn
		}
		
		// Process nodes in parallel (up to maxParallelENRRequests)
		iter = enode.AsyncFilter(iter, resolverFunc, maxParallelENRRequests)
		// Filter for nodes that support our protocols
		iter = enode.Filter(iter, eth.NewNodeFilter(s.blockchain))
		// Buffer some nodes for smooth connection flow
		iter = enode.NewBufferIter(iter, discoveryPrefetchBuffer)
		s.discmix.AddSource(iter)
	}

	// Add nodes from Discovery v5 (newer discovery protocol)
	if s.p2pServer.DiscoveryV5() != nil {
		// Create filter for compatible nodes
		filter := eth.NewNodeFilter(s.blockchain)
		// Get random nodes and filter them
		iter := enode.Filter(s.p2pServer.DiscoveryV5().RandomNodes(), filter)
		// Buffer for smooth connections
		iter = enode.NewBufferIter(iter, discoveryPrefetchBuffer)
		s.discmix.AddSource(iter)
	}

	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
// This is called when the node shuts down
func (s *Ethereum) Stop() error {
	// Stop networking first (no new data coming in)
	s.discmix.Close()      // Stop peer discovery
	s.dropper.Stop()       // Stop connection management
	s.handler.Stop()       // Stop protocol handling

	// Stop filter maps goroutine
	ch := make(chan struct{})
	s.closeFilterMaps <- ch
	<-ch  // Wait for it to finish
	
	// Stop core components
	s.filterMaps.Stop()    // Stop log indexing
	s.txPool.Close()       // Close transaction pool
	s.blockchain.Stop()    // Stop blockchain processing
	s.engine.Close()       // Stop consensus engine

	// Mark clean shutdown (must be before closing DB)
	s.shutdownTracker.Stop()

	// Finally close database and event system
	s.chainDb.Close()
	s.eventMux.Stop()

	return nil
}

// SyncMode retrieves the current sync mode, either explicitly set, or derived
// from the chain status.
// This determines how we sync: full (process all blocks) or snap (download state directly)
func (s *Ethereum) SyncMode() ethconfig.SyncMode {
	// Check if we're currently snap syncing
	if s.handler.snapSync.Load() {
		return ethconfig.SnapSync
	}
	
	// We might have been full syncing but rewound
	// Check if we need to switch back to snap sync
	head := s.blockchain.CurrentBlock()
	
	// Check if we're before the snap sync pivot point
	if pivot := rawdb.ReadLastPivotNumber(s.chainDb); pivot != nil {
		if head.Number.Uint64() < *pivot {
			// We're before pivot - use snap sync
			return ethconfig.SnapSync
		}
	}
	
	// Check if we have the state for the current head
	// If not, we need snap sync to download it
	if !s.blockchain.HasState(head.Root) {
		log.Info("Reenabled snap sync as chain is stateless")
		return ethconfig.SnapSync
	}
	
	// All good - we're full syncing
	return ethconfig.FullSync
}
