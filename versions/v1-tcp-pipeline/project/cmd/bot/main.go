// Command bot is the entry point. It loads the fleet roster (config.json or
// environment), spawns the manager layer, and runs each bot on an independent
// play/break schedule.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"packet-bot/internal/analytics"
	"packet-bot/internal/behavior"
	"packet-bot/internal/botlogic"
	"packet-bot/internal/camera"
	"packet-bot/internal/command"
	"packet-bot/internal/config"
	"packet-bot/internal/manager"
	"packet-bot/internal/motor"
	"packet-bot/internal/network"
	"packet-bot/internal/physiology"
	"packet-bot/internal/protocol"
	"packet-bot/internal/state"
	"packet-bot/internal/world"
	"packet-bot/pkg/logger"
)

const defaultServerAddr = "game.server.ip:43594"

// dialTimeout bounds the proxy/server connection attempt.
const dialTimeout = 15 * time.Second

// defaultClientRevision is used for login when CLIENT_REVISION is unset. It
// matches the JS5 handshake default; update both when the live game revision
// changes.
const defaultClientRevision uint32 = 239

// revenantExitBases are default zone escape tiles for panic-mode evasion.
// Override via bot config or collision map; order is shuffled per bot at runtime.
var revenantExitBases = []world.Position{
	{X: 3128, Y: 10122},
	{X: 3214, Y: 10118},
}

type runtimeFlags struct {
	configPath     string
	collision      string
	plane          int
	task           string
	analyticsDir   string
	traceDB        string
	intentDB       string
	clickOffsetsDB string
}

// Dev pipeline outputs (pass explicitly via --trace-db / --intent-db / --click-offsets):
//   mouse_dynamics_pipeline/out/lookup.json.gz
//   mouse_dynamics_pipeline/out/intent_train_sample.json.gz
//   mouse_dynamics_pipeline/out/click_offsets.json.gz

func main() {
	configPath := flag.String("config", "config.json", "path to fleet roster JSON")
	collisionPath := flag.String("collision", "", "path to collision dump (world-addressed pathfinding)")
	plane := flag.Int("plane", 0, "map plane (0-3) for collision data")
	task := flag.String("task", "woodcutter", "default task if not set per-bot: woodcutter | revenant")
	analyticsDir := flag.String("analytics-dir", "", "directory for per-bot packet telemetry logs (JSON lines); empty disables analytics")
	traceDB := flag.String("trace-db", "", "mined mouse-path lookup (build_db.py); empty disables spatial replay")
	intentDB := flag.String("intent-db", "", "deconvolved intent vectors (deconv_traces.py); empty disables neuromorphic motor")
	clickOffsetsDB := flag.String("click-offsets", "", "mined click-offset lookup (build_click_offsets.py); empty disables clustered aim")
	fleetSchedule := flag.Bool("fleet-schedule", false, "enable global time-scheduling (diurnal timetable + concurrency guard) instead of per-bot self-scheduling")
	maxOnlineFrac := flag.Float64("max-online-frac", 0.7, "max fraction of the fleet online at once (fleet-schedule only)")
	flag.Parse()

	if err := config.LoadDotEnv(".env"); err != nil && !os.IsNotExist(err) {
		logger.Default().Warnf("could not load .env: %v", err)
	}

	log := logger.Default()
	env := config.FromEnv()
	flags := runtimeFlags{configPath: *configPath, collision: *collisionPath, plane: *plane, task: *task, analyticsDir: *analyticsDir, traceDB: *traceDB, intentDB: *intentDB, clickOffsetsDB: *clickOffsetsDB}

	configs, err := resolveConfigs(*configPath, env, flags)
	if err != nil {
		log.Errorf("config: %v", err)
		os.Exit(1)
	}
	if len(configs) == 0 {
		log.Errorf("no bot configurations to run")
		os.Exit(1)
	}

	mgr := manager.NewManager(log)
	runners := make([]*manager.BotRunner, 0, len(configs))
	for _, bc := range configs {
		sess := newBotSession(bc, flags, log)
		runner := manager.NewBotRunner(bc, sess, log)
		mgr.Add(runner)
		runners = append(runners, runner)
	}

	log.Infof("manager starting %d bot(s)", len(configs))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Global time-scheduling: a single authority assigns each bot a diurnal
	// timetable (play/break/sleep) and enforces fleet-wide anti-synchronization.
	if *fleetSchedule {
		// Resolve orchestrator-wide tuning: defaults, overridden by any FLEET_*
		// env vars, then injected into the clock so the bounds cascade to every
		// generated timetable and the activity curve.
		tune := manager.TuningFromEnv(manager.DefaultTuning())
		clock := manager.DefaultFleetClock().WithTuning(tune)
		guard := manager.NewConcurrencyGuard(len(runners), *maxOnlineFrac, 90*time.Second)
		orch := manager.NewFleetOrchestrator(clock, guard, log)
		for _, r := range runners {
			orch.Attach(r, manager.GenerateTimetable(r.ID, clock.Now(), clock))
		}
		log.Infof("fleet scheduler enabled (max_online=%.0f%%, %d bots)", *maxOnlineFrac*100, len(runners))
		log.Infof("fleet tuning: peak=%.1fh floor=%.2f wake=%.1f-%.1fh bed=%.1f-%.1fh play=%d-%dm break=%d-%dm",
			tune.PeakHour, tune.ActivityFloor,
			tune.WakeMinHour, tune.WakeMaxHour,
			tune.BedMinHour, tune.BedMaxHour,
			tune.PlayMinM, tune.PlayMaxM,
			tune.BreakMinM, tune.BreakMaxM)
		go orch.Run(ctx)
	}

	// Periodic mode snapshot for operators / log scrapers.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for id, mode := range mgr.StatusSnapshot() {
					log.Infof("runner %s mode=%s", id, mode)
				}
			}
		}
	}()

	go mgr.RunAll(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Infof("shutting down")
	cancel()
	// Allow runners a moment to call Stop() on their sessions.
	time.Sleep(500 * time.Millisecond)
}

// resolveConfigs loads the roster from file and/or environment.
func resolveConfigs(path string, env config.Config, flags runtimeFlags) ([]manager.BotConfig, error) {
	var configs []manager.BotConfig

	if _, err := os.Stat(path); err == nil {
		loaded, err := manager.LoadConfig(path)
		if err != nil {
			return nil, err
		}
		configs = manager.FilterByID(loaded, env.BotID)
	}

	// Container / single-bot mode: synthesize one config from env when the file
	// is missing, empty, or BOT_ID did not match any row.
	if len(configs) == 0 && env.AccountUser != "" {
		bc := manager.BotConfig{
			BotID:                env.BotID,
			User:                 env.AccountUser,
			Pass:                 env.AccountPass,
			ProxyURL:             env.ProxyURL,
			Task:                 env.Task,
			ServerAddr:           env.ServerAddr,
			Schedule:             manager.Schedule{PlayH: 4, BreakM: 30},
			Revision:             env.Revision,
			RSAModulus:           env.RSAModulus,
			RSAExponent:          env.RSAExponent,
			ArchiveCRCs:          env.ArchiveCRCs,
			InventoryContainerID: env.InventoryContainerID,
		}
		if bc.Task == "" {
			bc.Task = flags.task
		}
		if err := bc.Normalize(); err != nil {
			return nil, err
		}
		configs = []manager.BotConfig{bc}
	}

	// Overlay runtime env onto file-loaded rows (Docker injects PROXY_URL, etc.).
	for i := range configs {
		if env.ProxyURL != "" {
			configs[i].ProxyURL = env.ProxyURL
		}
		if env.ServerAddr != "" {
			configs[i].ServerAddr = env.ServerAddr
		}
		if env.Task != "" {
			configs[i].Task = env.Task
		}
		if env.BotID != "" && configs[i].BotID == "" {
			configs[i].BotID = env.BotID
		}
		if env.AccountUser != "" {
			configs[i].User = env.AccountUser
			configs[i].Pass = env.AccountPass
		}
		if env.Revision != 0 {
			configs[i].Revision = env.Revision
		}
		if env.RSAModulus != "" {
			configs[i].RSAModulus = env.RSAModulus
		}
		if env.RSAExponent != "" {
			configs[i].RSAExponent = env.RSAExponent
		}
		if len(env.ArchiveCRCs) > 0 {
			configs[i].ArchiveCRCs = env.ArchiveCRCs
		}
	}

	for i := range configs {
		if err := configs[i].Normalize(); err != nil {
			return nil, err
		}
		log := logger.Default()
		p := configs[i].Personality.Normalize()
		bp := state.ResolveBehaviorProfile(configs[i].BehaviorProfile, configs[i].BotID, p)
		log.Infof("bot %q rostered (task=%s, account=%s, proxy=%s, play=%dh break=%dm, motor=%q, behavior=%q, personality risk=%.2f drift=%.2f distract=%.2f)",
			configs[i].BotID, configs[i].Task,
			config.MaskSecret(configs[i].User), config.MaskProxyURL(configs[i].ProxyURL),
			configs[i].Schedule.PlayH, configs[i].Schedule.BreakM,
			configs[i].Profile, bp.Name,
			p.RiskTolerance, p.DriftRate, p.DistractionRate)
	}
	return configs, nil
}

// botSession wires one bot's network stack and task FSM. It implements
// manager.Behavior and is restarted each active play window.
type botSession struct {
	cfg   manager.BotConfig
	flags runtimeFlags
	log   *logger.Logger

	// behavior persists across play/break cycles so fatigue accrues during play
	// and recovers during break, rather than resetting each session.
	behavior *command.BehavioralEngine
	cadence  *behavior.CadenceEngine
	uiWatch  *physiology.UIWatcher

	// viewProfile holds per-session, bot-unique view radii decoupled from the
	// global RenderDistance constant. Set at the start of each Run() cycle.
	viewProfile *world.ViewProfile

	mu            sync.Mutex
	agent         *command.Agent
	session       *network.Session
	collector     *analytics.Collector
	pruneCancel   context.CancelFunc
	profileCancel context.CancelFunc
}

func newBotSession(cfg manager.BotConfig, flags runtimeFlags, log *logger.Logger) *botSession {
	traits := cfg.Personality.Normalize()
	profileName := cfg.Profile
	if !command.HasProfile(profileName) {
		log.Warnf("session %s: unknown profile %q, using default", cfg.BotID, profileName)
		profileName = "default"
	}
	hum := command.NewHumanizerForTraits(profileName, traits, cfg.BotID)
	be := command.NewBehavioralEngineForTraits(hum, traits, cfg.BotID)
	var cadence *behavior.CadenceEngine
	if be.Physio != nil {
		cadence = behavior.NewCadenceEngine(be.Physio.CadenceSeed(), be.Physio.ModelZoo())
	}
	prof := hum.Profile()
	log.Infof("session %s: profile=%q motor P1=%.3f P2=%.3f drift=%.2f distract=%.2f risk=%.2f",
		cfg.BotID, profileName, prof.P1, prof.P2, traits.DriftRate, traits.DistractionRate, traits.RiskTolerance)
	return &botSession{cfg: cfg, flags: flags, log: log, behavior: be, cadence: cadence}
}

// Recover feeds rest time to the persistent behavioral engine during a break,
// satisfying manager.Recoverable.
func (b *botSession) Recover(dt time.Duration) {
	b.behavior.Recover(dt)
	b.log.Debugf("session %s: recovering, fatigue=%.3f", b.cfg.BotID, b.behavior.Fatigue())
}

func (b *botSession) Run(ctx context.Context) {
	b.log.Infof("session %s: connecting (task=%s)", b.cfg.BotID, b.cfg.Task)

	serverAddr := defaultServerAddr
	if b.cfg.ServerAddr != "" {
		serverAddr = b.cfg.ServerAddr
	}

	var matrix *world.Matrix
	if b.flags.collision != "" {
		matrix = world.NewWorldMatrix()
		regions, err := world.LoadCollisionFile(matrix, b.flags.collision, b.flags.plane)
		if err != nil {
			b.log.Errorf("collision load failed: %v", err)
			return
		}
		b.log.Infof("loaded collision for %d regions (plane %d)", regions, b.flags.plane)
	} else {
		matrix = world.NewMatrix()
	}
	matrix.SetRoutePersonality(b.cfg.BotID)

	// Bind the real inventory container id when configured, so inventory
	// tracking keys off the server-assigned id instead of the placeholder
	// default. Unset (0) leaves the world model's default in place.
	if b.cfg.InventoryContainerID != 0 {
		matrix.SetInventoryContainerID(b.cfg.InventoryContainerID)
		b.log.Infof("session %s: inventory container bound to %d", b.cfg.BotID, b.cfg.InventoryContainerID)
	}

	var sessOpts []network.Option
	sessOpts = append(sessOpts, network.WithBotIdentity(b.cfg.BotID))
	if b.cfg.ProxyURL != "" {
		dialer, err := network.NewDialer(b.cfg.ProxyURL, dialTimeout)
		if err != nil {
			b.log.Errorf("proxy setup failed: %v", err)
			return
		}
		sessOpts = append(sessOpts, network.WithDialer(dialer))
	}

	// Game login: only attempt real account authentication when an RSA public
	// key is configured (it is revision-specific and Jagex-controlled). Without
	// it the session falls back to the JS5 update handshake, which cannot enter
	// the world.
	if b.cfg.RSAModulus != "" {
		rsaKey, err := network.NewRSAPublicKey(b.cfg.RSAModulus, b.cfg.RSAExponent)
		if err != nil {
			b.log.Errorf("session %s: login RSA key invalid: %v", b.cfg.BotID, err)
			return
		}
		rev := b.cfg.Revision
		if rev == 0 {
			rev = defaultClientRevision
		}
		if len(b.cfg.ArchiveCRCs) == 0 {
			b.log.Warnf("session %s: no CLIENT_ARCHIVE_CRCS/archive_crcs set; live login may reject the client as out of date", b.cfg.BotID)
		}
		loginEnv := config.FromEnv()
		loginCfg := network.LoginConfig{
			Username:                   b.cfg.User,
			Password:                   b.cfg.Pass,
			Revision:                   rev,
			RSA:                        rsaKey,
			ArchiveCRCs:                b.cfg.ArchiveCRCs,
			ClientToken:                loginEnv.ClientToken,
			GameSessionToken:           loginEnv.GameSessionToken,
			Timeout:                    dialTimeout,
			RequireCapturedMachineInfo: network.RequireCapturedMachineInfoFromEnv(),
		}
		if listen := os.Getenv("HANDOFF_LISTEN"); listen != "" {
			waitSec := 900
			if v := os.Getenv("HANDOFF_WAIT_SEC"); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					waitSec = n
				}
			}
			b.log.Infof("session %s: waiting for live handoff on %s (up to %ds)", b.cfg.BotID, listen, waitSec)
			hctx, hcancel := context.WithTimeout(ctx, time.Duration(waitSec)*time.Second)
			handoff, herr := network.WaitForHandoff(hctx, listen, time.Duration(waitSec)*time.Second)
			hcancel()
			if herr != nil {
				b.log.Errorf("session %s: handoff failed: %v", b.cfg.BotID, herr)
				return
			}
			if err := handoff.ApplyToLoginConfig(&loginCfg); err != nil {
				b.log.Errorf("session %s: handoff apply failed: %v", b.cfg.BotID, err)
				return
			}
			b.log.Infof("session %s: handoff received pk len=%d wireBlocked=%v", b.cfg.BotID, len(loginCfg.GameSessionToken), handoff.WireBlocked)
		}
		if loginEnv.MachineInfoHex != "" {
			if mi, err := hex.DecodeString(strings.TrimSpace(loginEnv.MachineInfoHex)); err == nil {
				loginCfg.MachineInfo = mi
			}
		}
		if loginEnv.PlatformInfoHex != "" {
			if pi, err := hex.DecodeString(strings.TrimSpace(loginEnv.PlatformInfoHex)); err == nil && len(pi) == 24 {
				loginCfg.PlatformInfo = pi
			}
		}
		if v := os.Getenv("DEVICE_ID"); v != "" {
			if id, err := strconv.ParseUint(v, 10, 32); err == nil {
				loginCfg.DeviceID = uint32(id)
			}
		}
		// Just-in-time pk minting: when MINT_PK_JIT is set, mint a fresh
		// game-session token from the RuneLite credentials file on every login
		// attempt (including reconnects). The pk is short-lived, so minting at the
		// last moment avoids code 10 from an expired token — and picks up a
		// re-launched launcher session without restarting the bot.
		if mintJIT, _ := strconv.ParseBool(os.Getenv("MINT_PK_JIT")); mintJIT {
			credPath := os.Getenv("RUNELITE_CREDENTIALS")
			if credPath == "" {
				credPath = network.DefaultCredentialsPath()
			}
			loginCfg.PKMinter = network.NewCredentialsPKMinter(credPath, b.cfg.ProxyURL, dialTimeout)
			b.log.Infof("session %s: just-in-time pk minting enabled (creds=%s)", b.cfg.BotID, credPath)
		}
		sessOpts = append(sessOpts, network.WithLogin(loginCfg))
	} else {
		b.log.Warnf("session %s: no RSA_MODULUS set; using JS5 update handshake only (will NOT enter the game)", b.cfg.BotID)
	}

	// Packet telemetry: opt-in via --analytics-dir. Each bot writes a JSON-lines
	// log; the collector flushes asynchronously so the read/write loops never
	// block on telemetry I/O.
	var collector *analytics.Collector
	if b.flags.analyticsDir != "" {
		if err := os.MkdirAll(b.flags.analyticsDir, 0o755); err != nil {
			b.log.Errorf("session %s: analytics dir setup failed: %v", b.cfg.BotID, err)
		} else {
			logPath := filepath.Join(b.flags.analyticsDir, b.cfg.BotID+".jsonl")
			c, err := analytics.NewCollector(logPath)
			if err != nil {
				b.log.Errorf("session %s: analytics collector failed: %v", b.cfg.BotID, err)
			} else {
				collector = c
				sessOpts = append(sessOpts, network.WithAnalytics(c))
				b.log.Infof("session %s: packet telemetry -> %s", b.cfg.BotID, logPath)
			}
		}
	}

	if b.flags.traceDB != "" || b.flags.intentDB != "" {
		if prov, err := command.OpenTraceOrIntent(b.flags.traceDB, b.flags.intentDB); err != nil {
			b.log.Warnf("session %s: mouse trace backend disabled: %v (hover fallback)", b.cfg.BotID, err)
		} else if prov != nil {
			sessOpts = append(sessOpts, network.WithTraceProvider(prov))
			if b.flags.intentDB != "" {
				b.log.Infof("session %s: neuromorphic mouse traces <- %s", b.cfg.BotID, b.flags.intentDB)
			} else {
				b.log.Infof("session %s: mined mouse traces <- %s", b.cfg.BotID, b.flags.traceDB)
			}
		}
	}

	if b.flags.intentDB != "" {
		if db, err := motor.OpenIntentDB(b.flags.intentDB); err != nil {
			b.log.Warnf("session %s: motor intent DB disabled: %v", b.cfg.BotID, err)
		} else if db != nil {
			sessOpts = append(sessOpts, network.WithMotorIntent(db))
			b.log.Infof("session %s: motor intent camera sweeps <- %s (%d segments)", b.cfg.BotID, b.flags.intentDB, len(db.All))
		}
	}

	if b.flags.clickOffsetsDB != "" {
		if db, err := command.OpenClickOffsetsDB(b.flags.clickOffsetsDB); err != nil {
			b.log.Warnf("session %s: click offset clustering disabled: %v (bbox-center aim)", b.cfg.BotID, err)
		} else if db != nil {
			sessOpts = append(sessOpts, network.WithClickOffsets(db))
			b.log.Infof("session %s: click offset clustering <- %s", b.cfg.BotID, b.flags.clickOffsetsDB)
		}
	}

	behaviorProf := state.ResolveBehaviorProfile(b.cfg.BehaviorProfile, b.cfg.BotID, b.cfg.Personality)
	intervalProfile := intervalProfileIndexForBehavior(behaviorProf.Name)
	intervalContext := intervalContextIndexForTask(b.cfg.Task)
	sessOpts = append(sessOpts, network.WithBehaviorProfile(intervalProfile, intervalContext))
	if b.behavior != nil && b.behavior.Physio != nil {
		sessOpts = append(sessOpts, network.WithPhysioReader(b.behavior.Physio))
	}
	if b.cadence != nil {
		sessOpts = append(sessOpts, network.WithCadence(b.cadence))
	}
	b.log.Infof("session %s: cognitive hesitation profile=%s context=%s",
		b.cfg.BotID, behavior.Profiles[intervalProfile], behavior.Contexts[intervalContext])
	if b.cfg.Task == "revenant" {
		b.log.Infof("session %s: revenant uses combat interval context (runtime cap 60s downtime); "+
			"re-mine combat recordings with: py extract_intervals.py <combat_data> --profile high_intensity",
			b.cfg.BotID)
	}

	session := network.NewSession(serverAddr, sessOpts...)
	session.SetLogger(b.log)

	if b.behavior != nil && b.behavior.Physio != nil {
		b.uiWatch = physiology.NewUIWatcher(b.behavior.Physio)
		b.uiWatch.BindVisibilityHooks(matrix)
	}

	if b.cfg.BehaviorProfile != "" && !state.HasBehaviorProfile(b.cfg.BehaviorProfile) {
		b.log.Warnf("session %s: unknown behavior_profile %q, resolved to %q",
			b.cfg.BotID, b.cfg.BehaviorProfile, behaviorProf.Name)
	}
	b.log.Infof("session %s: behavior profile %q (loot_thresh=%d, threat_near=%d)",
		b.cfg.BotID, behaviorProf.Name, behaviorProf.Loot.Threshold, behaviorProf.Threat.ProximityNear)

	threat := state.NewThreatEngine(matrix, behaviorProf.Threat, state.StochasticSeedFromBotID(b.cfg.BotID))

	// Threat-dominant safety wrapper: one object answers under-threat, opponent
	// weapon, evasion priority, and teleblock for the bot logic. The Stochastic
	// stream jitters threat-persistence windows for anti-fingerprinting.
	safety := state.NewSafetyOrchestrator(matrix, threat, state.StochasticSeedFromBotID(b.cfg.BotID), b.cfg.Personality)

	threat.SetEscapeHandler(func(level state.Level) {
		score, name := threat.Top()
		b.log.Warnf("THREAT %s (score=%d, player=%q); panic-pathfind (no instant logout)", level, score, name)
		safety.RefreshThreatRegistry()
	})

	viewProf := world.NewViewProfile(b.cfg.BotID, world.RenderDistance)
	lootR, entityR, itemR := viewProf.Baselines()
	b.log.Infof("session %s: view profile baselines loot=%d entity=%d item=%d",
		b.cfg.BotID, lootR, entityR, itemR)

	lootCfg := behaviorProf.Loot
	lootCfg.ViewRadius = viewProf.CurrentLootRadius()
	lootCfg.FleetMateUsers = fleetMateUsers(b.flags.configPath, b.cfg.User)
	loot := state.NewLootEngine(matrix, lootCfg, state.StochasticSeedFromBotID(b.cfg.BotID), b.cfg.Personality)
	loot.BindPKClassifier(threat.IsPKer)
	if b.behavior != nil && b.behavior.Physio != nil {
		loot.BindPhysio(b.behavior.Physio)
	}
	b.viewProfile = viewProf

	var profileSch *state.ProfileScheduler
	if b.cfg.BehaviorRotateEnabled() {
		profileCtx, profileCancel := context.WithCancel(ctx)
		shifts := state.DefaultProfileShifts()
		// If the bot starts on a non-cautious profile, begin the rotation there.
		if behaviorProf.Name != shifts[0].Profile {
			shifts[0].Profile = behaviorProf.Name
		}
		profileSch = state.NewProfileScheduler(b.cfg.BotID, loot, threat, shifts, b.log)
		go profileSch.Run(profileCtx)
		b.mu.Lock()
		b.profileCancel = profileCancel
		b.mu.Unlock()
	}
	// Reuse the persistent behavioral engine so fatigue carries across sessions.
	agent := command.NewAgentWithBehavior(session, b.log, b.behavior)
	visExec := session.NewExecutor(state.NewStochasticFromSeed(state.StochasticSeedFromBotID(b.cfg.BotID) ^ 0x766973))
	loot.BindCamera(func() *camera.Model {
		if visExec != nil {
			return visExec.Camera
		}
		return nil
	})
	b.log.Infof("session %s: resuming at fatigue=%.3f", b.cfg.BotID, b.behavior.Fatigue())
	matrix.OnPlayerEvent(func() {
		threat.ForceEvaluate()
		safety.RefreshThreatRegistry()
	})

	dispatcher := protocol.NewDispatcher(matrix, b.log)
	session.OnPacket(dispatcher.Dispatch)

	pruneCtx, pruneCancel := context.WithCancel(ctx)
	go b.pruneLoop(pruneCtx, matrix, loot, session)

	b.mu.Lock()
	b.agent = agent
	b.session = session
	b.collector = collector
	b.pruneCancel = pruneCancel
	b.mu.Unlock()

	defer b.teardown()

	switch b.cfg.Task {
	case "revenant":
		// Register zone escape tiles used by panic-mode evasion. These are the
		// cave portal / exit ditch coordinates in the collision data's space;
		// adjust to match the loaded map. The fallback (flee away from PKer)
		// still works if this list is empty.
		matrix.SetExitPoints(world.PersonalizedExitPoints(b.cfg.BotID, revenantExitBases))
		botlogic.StartRevenantKiller(ctx, session, agent, matrix, safety, loot, b.cfg.Personality, b.cfg.BotID)
	case "woodcutter":
		botlogic.StartWoodcutter(ctx, session, matrix, threat, agent, b.behavior.Humanizer(), b.cfg.Profile, b.cfg.Personality, b.cfg.BotID)
	default:
		b.log.Errorf("unknown task %q", b.cfg.Task)
	}
}

func (b *botSession) Stop() {
	b.log.Infof("session %s: stopping (scheduled break or shutdown)", b.cfg.BotID)
	b.mu.Lock()
	if b.agent != nil {
		b.agent.Submit(command.Command{
			Name:     "scheduled-logout",
			TaskKind: command.TaskThreat,
			Op:       protocol.OpIdleLogout,
			Priority: command.PriorityCritical,
			Primary:  true,
		})
	} else if b.session != nil {
		b.session.Send(protocol.OpIdleLogout, nil)
	}
	b.mu.Unlock()
	b.teardown()
}

func (b *botSession) teardown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pruneCancel != nil {
		b.pruneCancel()
		b.pruneCancel = nil
	}
	if b.profileCancel != nil {
		b.profileCancel()
		b.profileCancel = nil
	}
	if b.agent != nil {
		b.agent.Close()
		b.agent = nil
	}
	if b.session != nil {
		b.session.Close()
		b.session = nil
	}
	if b.collector != nil {
		b.collector.Close()
		b.collector = nil
	}
}

func (b *botSession) pruneLoop(ctx context.Context, matrix *world.Matrix, loot *state.LootEngine, session *network.Session) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			dt := now.Sub(last)
			if b.behavior != nil && b.behavior.Physio != nil {
				snap := b.behavior.Physio.Tick(dt)
				if b.cadence != nil {
					b.cadence.ApplyRegime(snap.Regime, b.behavior.Physio.ModelZoo())
				}
			} else if b.behavior != nil {
				b.behavior.TickFatigue(dt)
			}
			if b.uiWatch != nil {
				b.uiWatch.Tick(matrix)
			}
			if session != nil {
				if exec := session.MotorExec(); exec != nil && b.behavior != nil && b.behavior.Physio != nil {
					go command.MaybeSovereignPeripheral(context.Background(), b.behavior.Physio, exec)
				}
			}
			last = now

			self := matrix.SelfPos()
			if self.X == 0 && self.Y == 0 {
				continue
			}
			vp := b.viewProfile
			if vp == nil {
				continue
			}
			if removed := matrix.PruneEntities(self, vp.CurrentEntityRadius()); removed > 0 {
				b.log.Debugf("pruned %d entities", removed)
			}
			if removed := matrix.PruneGroundItems(self, vp.CurrentItemRadius()); removed > 0 {
				b.log.Debugf("pruned %d ground items", removed)
			}
			matrix.PruneWalkHistory()
			b.syncLootViewRadius(loot)
		}
	}
}

// syncLootViewRadius pushes a fresh jittered loot radius into the engine without
// disturbing the rest of the behavior profile config. ProfileScheduler rotations
// may reset ViewRadius to the registry default; this re-applies the per-bot
// view profile on every prune tick so loot targeting stays decoupled.
func (b *botSession) syncLootViewRadius(loot *state.LootEngine) {
	if loot == nil || b.viewProfile == nil {
		return
	}
	cfg := loot.Config()
	cfg.ViewRadius = b.viewProfile.CurrentLootRadius()
	loot.SetConfig(cfg)
}

func intervalProfileIndexForBehavior(name string) int {
	switch name {
	case "aggressive":
		if i := behavior.ProfileIndex("fast_efficient"); i >= 0 {
			return i
		}
	case "cautious":
		if i := behavior.ProfileIndex("methodical"); i >= 0 {
			return i
		}
	case "efficient":
		if i := behavior.ProfileIndex("average"); i >= 0 {
			return i
		}
	case "balanced":
		if i := behavior.ProfileIndex("average"); i >= 0 {
			return i
		}
	}
	if i := behavior.ProfileIndex(name); i >= 0 {
		return i
	}
	if i := behavior.ProfileIndex("average"); i >= 0 {
		return i
	}
	return 0
}

func intervalContextIndexForTask(task string) int {
	switch task {
	case "revenant":
		if i := behavior.ContextIndex("combat"); i >= 0 {
			return i
		}
	case "woodcutter":
		if i := behavior.ContextIndex("idle_skilling"); i >= 0 {
			return i
		}
	}
	if i := behavior.ContextIndex("idle_skilling"); i >= 0 {
		return i
	}
	return 0
}

// fleetMateUsers returns roster usernames excluding self so loot danger multipliers
// ignore co-located fleet bots.
func fleetMateUsers(configPath, selfUser string) []string {
	if configPath == "" || selfUser == "" {
		return nil
	}
	loaded, err := manager.LoadConfig(configPath)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(loaded))
	for _, row := range loaded {
		u := strings.TrimSpace(row.User)
		if u == "" || strings.EqualFold(u, selfUser) {
			continue
		}
		out = append(out, u)
	}
	return out
}
