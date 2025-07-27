// geth is a command-line client for Ethereum.
// This is the MAIN ENTRY POINT for the entire Ethereum node - when you run `geth`, this code executes first
package main

import (
	"fmt"     // For printing output to console
	"os"      // For interacting with operating system (getting command-line args, exiting)
	"slices"  // For slice operations like concatenation
	"sort"    // For sorting commands alphabetically
	"strconv" // For converting strings to integers (cache size)
	"time"    // For time operations (checking sync status)

	// Go-Ethereum specific packages
	"github.com/ethereum/go-ethereum/accounts"       // For managing Ethereum accounts and wallets
	"github.com/ethereum/go-ethereum/cmd/utils"      // Command-line utilities and flag definitions
	"github.com/ethereum/go-ethereum/common"         // Common Ethereum types and utilities
	"github.com/ethereum/go-ethereum/console/prompt" // For interactive console input
	"github.com/ethereum/go-ethereum/eth/downloader" // For blockchain synchronization events
	"github.com/ethereum/go-ethereum/ethclient"      // Ethereum RPC client for wallet interaction
	"github.com/ethereum/go-ethereum/internal/debug" // Debug and logging utilities
	"github.com/ethereum/go-ethereum/internal/flags" // Command-line flag management
	"github.com/ethereum/go-ethereum/log"            // Logging functionality
	"github.com/ethereum/go-ethereum/node"           // Core node infrastructure
	"go.uber.org/automaxprocs/maxprocs"              // Automatically sets GOMAXPROCS to match container CPU limits

	// Force-load the tracer engines to trigger registration
	// These blank imports ensure tracer engines are registered at startup even if not directly used
	_ "github.com/ethereum/go-ethereum/eth/tracers/js"     // JavaScript-based transaction tracer
	_ "github.com/ethereum/go-ethereum/eth/tracers/live"   // Live/streaming transaction tracer
	_ "github.com/ethereum/go-ethereum/eth/tracers/native" // Native Go transaction tracer

	"github.com/urfave/cli/v2" // Command-line interface framework
)

const (
	// clientIdentifier is what this node calls itself when connecting to other Ethereum nodes
	// Other nodes will see connections from "geth/v1.x.x/linux/go1.x"
	clientIdentifier = "geth"
)

var (
	// nodeFlags contains all command-line flags that configure the Ethereum node itself
	// These control everything from networking to transaction pool to blockchain settings
	nodeFlags = slices.Concat([]cli.Flag{
		// Node identity and account management
		utils.IdentityFlag,            // Custom node name (shown to peers)
		utils.UnlockedAccountFlag,     // Account to unlock at startup (deprecated - security risk)
		utils.PasswordFileFlag,        // File containing account passwords
		utils.BootnodesFlag,           // Bootstrap nodes to connect to initially
		utils.MinFreeDiskSpaceFlag,    // Minimum free disk space required
		utils.KeyStoreDirFlag,         // Directory for account key files
		utils.ExternalSignerFlag,      // URL of external signer (like Clef)
		utils.NoUSBFlag,               // deprecated - Disable USB hardware wallets
		utils.USBFlag,                 // Enable USB hardware wallet support
		utils.SmartCardDaemonPathFlag, // Path to smartcard daemon
		utils.OverrideOsaka,           // Override Osaka hardfork activation
		utils.OverrideVerkle,          // Override Verkle tree activation
		utils.EnablePersonal,          // deprecated - Enable personal namespace
		// Transaction pool configuration
		utils.TxPoolLocalsFlag,       // Addresses always allowed to send transactions
		utils.TxPoolNoLocalsFlag,     // Disable local transaction handling
		utils.TxPoolJournalFlag,      // File to save local transactions across restarts
		utils.TxPoolRejournalFlag,    // How often to save the transaction journal
		utils.TxPoolPriceLimitFlag,   // Minimum gas price for transactions
		utils.TxPoolPriceBumpFlag,    // Minimum price bump for transaction replacement
		utils.TxPoolAccountSlotsFlag, // Max transactions per account in pool
		utils.TxPoolGlobalSlotsFlag,  // Max total transactions in pool
		utils.TxPoolAccountQueueFlag, // Max queued transactions per account
		utils.TxPoolGlobalQueueFlag,  // Max total queued transactions
		utils.TxPoolLifetimeFlag,     // How long transactions stay in pool
		utils.BlobPoolDataDirFlag,    // Where to store blob transaction data
		utils.BlobPoolDataCapFlag,    // Max disk space for blob transactions
		utils.BlobPoolPriceBumpFlag,  // Price bump for blob transaction replacement,
		// Sync and storage configuration
		utils.SyncModeFlag,             // Sync mode: full, snap, or light
		utils.SyncTargetFlag,           // Target block to sync to
		utils.ExitWhenSyncedFlag,       // Exit after blockchain is synced
		utils.GCModeFlag,               // Blockchain garbage collection mode
		utils.SnapshotFlag,             // Enable snapshot-based sync
		utils.TxLookupLimitFlag,        // deprecated - How many recent blocks to index
		utils.TransactionHistoryFlag,   // How many recent blocks to keep transaction index
		utils.ChainHistoryFlag,         // How many blocks to keep as blockchain history
		utils.LogHistoryFlag,           // Enable logging history for filtering
		utils.LogNoHistoryFlag,         // Disable automatic filter log history
		utils.LogExportCheckpointsFlag, // Export filter log checkpoints
		utils.StateHistoryFlag,         // How many recent blocks to keep state history
		utils.LightKDFFlag,             // Use lighter KDF for testing (INSECURE!)
		utils.EthRequiredBlocksFlag,    // Required blocks for sync validation
		utils.LegacyWhitelistFlag,      // deprecated - Fork block whitelist
		// Cache and memory configuration
		utils.CacheFlag,              // Total cache memory allowance in MB
		utils.CacheDatabaseFlag,      // Percentage of cache for database
		utils.CacheTrieFlag,          // Percentage of cache for trie nodes
		utils.CacheTrieJournalFlag,   // deprecated - Trie cache journal directory
		utils.CacheTrieRejournalFlag, // deprecated - How often to save trie journal
		utils.CacheGCFlag,            // Percentage of cache for garbage collection
		utils.CacheSnapshotFlag,      // Percentage of cache for snapshots
		utils.CacheNoPrefetchFlag,    // Disable heuristic state prefetch
		utils.CachePreimagesFlag,     // Enable caching of trie key preimages
		utils.CacheLogSizeFlag,       // Size of filter log cache
		utils.FDLimitFlag,            // File descriptor limit for database
		utils.CryptoKZGFlag,          // KZG library implementation to use,
		// Network configuration
		utils.ListenPortFlag,      // TCP port for P2P connections
		utils.DiscoveryPortFlag,   // UDP port for P2P discovery
		utils.MaxPeersFlag,        // Maximum number of network peers
		utils.MaxPendingPeersFlag, // Maximum pending peer connections

		// Mining/Validator configuration
		utils.MiningEnabledFlag,            // deprecated - Enable mining
		utils.MinerGasLimitFlag,            // Target gas limit for mined blocks
		utils.MinerGasPriceFlag,            // Minimum gas price for mining
		utils.MinerEtherbaseFlag,           // deprecated - Address for mining rewards
		utils.MinerExtraDataFlag,           // Extra data to include in blocks
		utils.MinerRecommitIntervalFlag,    // How often to recreate mining work
		utils.MinerPendingFeeRecipientFlag, // Address for pending block fees
		utils.MinerNewPayloadTimeoutFlag,   // deprecated - Timeout for payload creation
		// P2P network settings
		utils.NATFlag,               // NAT port mapping mechanism
		utils.NoDiscoverFlag,        // Disable peer discovery
		utils.DiscoveryV4Flag,       // Enable v4 discovery protocol
		utils.DiscoveryV5Flag,       // Enable v5 discovery protocol
		utils.LegacyDiscoveryV5Flag, // deprecated - Old discovery v5
		utils.NetrestrictFlag,       // Restrict network communication to specific IPs
		utils.NodeKeyFileFlag,       // P2P node key file
		utils.NodeKeyHexFlag,        // P2P node key as hex
		utils.DNSDiscoveryFlag,      // DNS-based peer discovery URLs,
		// Developer and debug settings
		utils.DeveloperFlag,         // Enable developer mode (instant mining)
		utils.DeveloperGasLimitFlag, // Gas limit for dev mode blocks
		utils.DeveloperPeriodFlag,   // Block time in dev mode
		utils.VMEnableDebugFlag,     // Enable VM debug output
		utils.VMTraceFlag,           // Enable VM execution tracing
		utils.VMTraceJsonConfigFlag, // VM trace configuration
		utils.NetworkIdFlag,         // Network ID to use
		utils.EthStatsURLFlag,       // Ethstats service URL for reporting,
		// Gas price oracle settings (for suggesting gas prices)
		utils.GpoBlocksFlag,         // Blocks to check for gas prices
		utils.GpoPercentileFlag,     // Percentile of gas prices to use
		utils.GpoMaxGasPriceFlag,    // Maximum gas price oracle will suggest
		utils.GpoIgnoreGasPriceFlag, // Gas price below which to ignore transactions

		// General configuration
		configFileFlag,           // TOML config file
		utils.LogDebugFlag,       // Prepend debug info to logs
		utils.LogBacktraceAtFlag, // Add backtraces to specific log messages,
		// Beacon chain light client settings
		utils.BeaconApiFlag,            // Beacon chain API endpoints
		utils.BeaconApiHeaderFlag,      // HTTP header for beacon API
		utils.BeaconThresholdFlag,      // Minimum sync committee participation
		utils.BeaconNoFilterFlag,       // Disable IP filtering for beacon API
		utils.BeaconConfigFlag,         // Beacon chain config file
		utils.BeaconGenesisRootFlag,    // Beacon chain genesis validator root
		utils.BeaconGenesisTimeFlag,    // Beacon chain genesis time
		utils.BeaconCheckpointFlag,     // Beacon chain checkpoint block root
		utils.BeaconCheckpointFileFlag, // Beacon chain checkpoint file
	}, utils.NetworkFlags, utils.DatabaseFlags) // Also include network selection and database flags

	// rpcFlags contains all RPC/API related configuration flags
	rpcFlags = []cli.Flag{
		// HTTP RPC settings
		utils.HTTPEnabledFlag,    // Enable HTTP-RPC server
		utils.HTTPListenAddrFlag, // HTTP-RPC server listening address
		utils.HTTPPortFlag,       // HTTP-RPC server port (default 8545)
		utils.HTTPCORSDomainFlag, // Domains allowed to make cross-origin requests

		// Authenticated RPC settings (for engine API)
		utils.AuthListenFlag,       // Listening address for authenticated APIs
		utils.AuthPortFlag,         // Port for authenticated APIs (default 8551)
		utils.AuthVirtualHostsFlag, // Virtual hostnames for authenticated APIs
		utils.JWTSecretFlag,        // JWT secret file for authenticated APIs

		// HTTP settings continued
		utils.HTTPVirtualHostsFlag,    // Virtual hostnames allowed for HTTP-RPC
		utils.GraphQLEnabledFlag,      // Enable GraphQL API
		utils.GraphQLCORSDomainFlag,   // CORS domains for GraphQL
		utils.GraphQLVirtualHostsFlag, // Virtual hostnames for GraphQL
		utils.HTTPApiFlag,             // Which RPC APIs to expose via HTTP
		utils.HTTPPathPrefixFlag,      // HTTP path prefix for RPC

		// WebSocket RPC settings
		utils.WSEnabledFlag,        // Enable WebSocket-RPC server
		utils.WSListenAddrFlag,     // WebSocket server listening address
		utils.WSPortFlag,           // WebSocket server port (default 8546)
		utils.WSApiFlag,            // APIs to expose via WebSocket
		utils.WSAllowedOriginsFlag, // Origins allowed for WebSocket
		utils.WSPathPrefixFlag,     // WebSocket path prefix

		// IPC (Inter-Process Communication) settings
		utils.IPCDisabledFlag, // Disable IPC-RPC server
		utils.IPCPathFlag,     // IPC socket/pipe path

		// RPC security and limits
		utils.InsecureUnlockAllowedFlag, // Allow account unlocking via RPC (DANGEROUS!)
		utils.RPCGlobalGasCapFlag,       // Global gas cap for RPC calls
		utils.RPCGlobalEVMTimeoutFlag,   // Global timeout for RPC EVM execution
		utils.RPCGlobalTxFeeCapFlag,     // Global transaction fee cap for RPC
		utils.AllowUnprotectedTxs,       // Allow non-EIP155 transactions
		utils.BatchRequestLimit,         // Maximum RPC batch request size
		utils.BatchResponseMaxSize,      // Maximum RPC batch response size
	}

	// metricsFlags contains monitoring and metrics configuration
	metricsFlags = []cli.Flag{
		// Basic metrics settings
		utils.MetricsEnabledFlag,          // Enable metrics collection
		utils.MetricsEnabledExpensiveFlag, // Enable expensive metrics
		utils.MetricsHTTPFlag,             // Expose metrics via HTTP
		utils.MetricsPortFlag,             // Metrics HTTP server port

		// InfluxDB v1 settings (for metrics export)
		utils.MetricsEnableInfluxDBFlag,   // Enable InfluxDB export
		utils.MetricsInfluxDBEndpointFlag, // InfluxDB endpoint URL
		utils.MetricsInfluxDBDatabaseFlag, // InfluxDB database name
		utils.MetricsInfluxDBUsernameFlag, // InfluxDB username
		utils.MetricsInfluxDBPasswordFlag, // InfluxDB password
		utils.MetricsInfluxDBTagsFlag,     // Extra tags for metrics

		// InfluxDB v2 settings
		utils.MetricsEnableInfluxDBV2Flag,     // Enable InfluxDB v2
		utils.MetricsInfluxDBTokenFlag,        // InfluxDB v2 auth token
		utils.MetricsInfluxDBBucketFlag,       // InfluxDB v2 bucket
		utils.MetricsInfluxDBOrganizationFlag, // InfluxDB v2 organization
	}
)

// app is the main CLI application instance that handles all commands and flags
var app = flags.NewApp("the go-ethereum command line interface")

// init runs before main() and sets up the entire CLI application structure
func init() {
	// Set the default action when running 'geth' with no subcommands
	app.Action = geth

	// Define all available subcommands
	app.Commands = []*cli.Command{
		// Blockchain management commands (defined in chaincmd.go)
		initCommand,            // Initialize a new genesis block
		importCommand,          // Import blockchain from file
		exportCommand,          // Export blockchain to file
		importHistoryCommand,   // Import historical state data
		exportHistoryCommand,   // Export historical state data
		importPreimagesCommand, // Import trie preimages
		removedbCommand,        // Remove blockchain and state databases
		dumpCommand,            // Dump a specific block from storage
		dumpGenesisCommand,     // Dump genesis block JSON
		pruneHistoryCommand,    // Prune historical state data
		downloadEraCommand,     // Download Era archives of chain history,
		// Account management commands (defined in accountcmd.go)
		accountCommand, // Manage accounts (create, list, update)
		walletCommand,  // Manage hardware wallets

		// Interactive console commands (defined in consolecmd.go)
		consoleCommand,    // Start an interactive JavaScript console
		attachCommand,     // Attach to a running geth instance
		javascriptCommand, // Execute JavaScript files

		// Miscellaneous commands (defined in misccmd.go)
		versionCommand,      // Print version information
		versionCheckCommand, // Check if updates are available
		licenseCommand,      // Display license information

		// Configuration command (defined in config.go)
		dumpConfigCommand, // Export configuration to TOML file

		// Database commands (defined in dbcmd.go)
		dbCommand, // Low-level database operations

		// Show deprecated flags (defined in cmd/utils/flags_legacy.go)
		utils.ShowDeprecated, // List all deprecated flags

		// Snapshot commands (defined in snapshot.go)
		snapshotCommand, // Manage blockchain snapshots

		// Verkle tree commands (defined in verkle.go)
		verkleCommand, // Verkle tree migration utilities,
	}

	// Add test command if available (only in certain builds)
	if logTestCommand != nil {
		app.Commands = append(app.Commands, logTestCommand)
	}

	// Sort commands alphabetically for help display
	sort.Sort(cli.CommandsByName(app.Commands))

	// Combine all flag groups into the main app
	app.Flags = slices.Concat(
		nodeFlags,    // Node operation flags
		rpcFlags,     // RPC server flags
		consoleFlags, // Console flags
		debug.Flags,  // Debug and logging flags
		metricsFlags, // Metrics collection flags
	)

	// Enable environment variable support for all flags
	// e.g., --datadir can be set via GETH_DATADIR env var
	flags.AutoEnvVars(app.Flags, "GETH")

	// app.Before runs before any command execution
	app.Before = func(ctx *cli.Context) error {
		// Automatically set GOMAXPROCS to match container CPU limits
		// This ensures geth doesn't try to use more CPUs than allocated
		maxprocs.Set()

		// Handle global flags that might be in the wrong position
		flags.MigrateGlobalFlags(ctx)

		// Set up debug logging and profiling based on flags
		if err := debug.Setup(ctx); err != nil {
			return err
		}

		// Warn about any unknown environment variables
		flags.CheckEnvVars(ctx, app.Flags, "GETH")
		return nil
	}
	// app.After runs after any command completes
	app.After = func(ctx *cli.Context) error {
		// Clean up debug systems (profiling, tracing)
		debug.Exit()

		// Reset terminal to normal mode (in case console was used)
		prompt.Stdin.Close()
		return nil
	}
}

// main is the program entry point - this is where everything starts!
func main() {
	// Run the CLI app with command-line arguments
	if err := app.Run(os.Args); err != nil {
		// If any error occurs, print it to stderr and exit with code 1
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// If we get here, everything ran successfully
}

// prepare does pre-startup configuration, particularly for mainnet nodes
// It adjusts cache settings and logs which network we're connecting to
func prepare(ctx *cli.Context) {
	// Log which network we're connecting to for user clarity
	switch {
	case ctx.IsSet(utils.SepoliaFlag.Name):
		// Sepolia is a proof-of-stake testnet
		log.Info("Starting Geth on Sepolia testnet...")

	case ctx.IsSet(utils.HoleskyFlag.Name):
		// Holesky is a testnet for staking and infrastructure
		log.Info("Starting Geth on Holesky testnet...")

	case ctx.IsSet(utils.HoodiFlag.Name):
		// Hoodi is an experimental testnet
		log.Info("Starting Geth on Hoodi testnet...")

	case !ctx.IsSet(utils.NetworkIdFlag.Name):
		// No network specified means mainnet
		log.Info("Starting Geth on Ethereum mainnet...")
	}
	// Mainnet nodes need more cache for better performance
	// If user didn't specify cache size and we're on mainnet, increase it
	if !ctx.IsSet(utils.CacheFlag.Name) && !ctx.IsSet(utils.NetworkIdFlag.Name) {
		// Double-check we're not on any testnet
		if !ctx.IsSet(utils.HoleskyFlag.Name) &&
			!ctx.IsSet(utils.SepoliaFlag.Name) &&
			!ctx.IsSet(utils.HoodiFlag.Name) &&
			!ctx.IsSet(utils.DeveloperFlag.Name) {
			// Definitely mainnet - bump cache from default to 4GB
			// This improves sync speed and overall performance
			log.Info("Bumping default cache on mainnet", "provided", ctx.Int(utils.CacheFlag.Name), "updated", 4096)
			ctx.Set(utils.CacheFlag.Name, strconv.Itoa(4096))
		}
	}
}

// geth is the main entry point into the system if no special subcommand is run.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func geth(ctx *cli.Context) error {
	// Check if user provided unknown commands
	if args := ctx.Args().Slice(); len(args) > 0 {
		return fmt.Errorf("invalid command: %q", args[0])
	}

	// Do pre-startup configuration
	prepare(ctx)

	// Create the full Ethereum node with all services
	stack := makeFullNode(ctx)
	defer stack.Close() // Ensure cleanup on exit

	// Start the node and all its services
	startNode(ctx, stack, false) // false = not in console mode

	// Wait for shutdown signal (Ctrl+C or kill)
	stack.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it starts the RPC/IPC interfaces and the miner.
func startNode(ctx *cli.Context, stack *node.Node, isConsole bool) {
	// Start the node - this starts P2P, database, blockchain, etc.
	utils.StartNode(ctx, stack, isConsole)

	// Warn about deprecated unlock flag (unlocking accounts via CLI is insecure)
	if ctx.IsSet(utils.UnlockedAccountFlag.Name) {
		log.Warn(`The "unlock" flag has been deprecated and has no effect`)
	}

	// Set up wallet management - watches for hardware wallets being connected
	// Create event channel with buffer of 16 to avoid blocking
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	// Create RPC clients to interact with our own node
	// This is used for wallet derivation paths
	rpcClient := stack.Attach()
	ethClient := ethclient.NewClient(rpcClient)

	// Start goroutine to handle wallet events
	go func() {
		// First, try to open any wallets already connected at startup
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet events until the node shuts down
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				// New wallet detected (e.g., USB device plugged in)
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}

			case accounts.WalletOpened:
				// Wallet successfully opened
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				// Set up derivation paths for HD wallets
				// Different hardware wallets use different paths
				var derivationPaths []accounts.DerivationPath
				if event.Wallet.URL().Scheme == "ledger" {
					// Ledger wallets need legacy path for compatibility
					derivationPaths = append(derivationPaths, accounts.LegacyLedgerBaseDerivationPath)
				}
				// Add standard Ethereum derivation path
				derivationPaths = append(derivationPaths, accounts.DefaultBaseDerivationPath)

				// Start deriving addresses in the background
				event.Wallet.SelfDerive(derivationPaths, ethClient)

			case accounts.WalletDropped:
				// Wallet disconnected (e.g., USB device removed)
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// If --exitwhensynced flag is set, monitor sync progress and exit when done
	// This is useful for scripted deployments
	if ctx.Bool(utils.ExitWhenSyncedFlag.Name) {
		go func() {
			// Subscribe to blockchain sync completion events
			sub := stack.EventMux().Subscribe(downloader.DoneEvent{})
			defer sub.Unsubscribe()

			for {
				event := <-sub.Chan()
				if event == nil {
					continue
				}

				// Check if this is really a DoneEvent
				done, ok := event.Data.(downloader.DoneEvent)
				if !ok {
					continue
				}

				// Exit only if we're synced to within 10 minutes of current time
				// This prevents premature exit on old chains
				if timestamp := time.Unix(int64(done.Latest.Time), 0); time.Since(timestamp) < 10*time.Minute {
					log.Info("Synchronisation completed", "latestnum", done.Latest.Number, "latesthash", done.Latest.Hash(),
						"age", common.PrettyAge(timestamp))
					stack.Close() // Trigger shutdown
				}
			}
		}()
	}
}
