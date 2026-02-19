import React, { useState, useEffect, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { GoogleGenAI, Type, Modality, LiveServerMessage } from '@google/genai';
import JSZip from 'https://esm.sh/jszip@3.10.1';

// Initialize Gemini API
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type SandboxStatus = 'IDLE' | 'ANALYZING' | 'DETONATED' | 'PURGED';
type DNSAuditStatus = 'IDLE' | 'TESTING' | 'SECURE' | 'LEAK_DETECTED';

// --- Audio Utilities ---
function encode(bytes: Uint8Array) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function decode(base64: string) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

async function decodeAudioData(
  data: Uint8Array,
  ctx: AudioContext,
  sampleRate: number,
  numChannels: number,
): Promise<AudioBuffer> {
  const dataInt16 = new Int16Array(data.buffer);
  const frameCount = dataInt16.length / numChannels;
  const buffer = ctx.createBuffer(numChannels, frameCount, sampleRate);

  for (let channel = 0; channel < numChannels; channel++) {
    const channelData = buffer.getChannelData(channel);
    for (let i = 0; i < frameCount; i++) {
      channelData[i] = dataInt16[i * numChannels + channel] / 32768.0;
    }
  }
  return buffer;
}

// --- Types & Interfaces ---
interface Alert {
  id: string;
  type: 'INFO' | 'WARNING' | 'CRITICAL' | 'SUCCESS';
  message: string;
  timestamp: number;
}

interface Block {
  index: number;
  timestamp: string;
  hash: string;
  prevHash: string;
  data: string;
}

interface FeatureFlag {
  flag: string;
  desc: string;
  cmd: string;
  category: string;
}

interface SandboxProcess {
  pid: number;
  name: string;
  risk: number;
  status: 'CONTAINED' | 'MONITORING' | 'SUSPICIOUS';
}

interface DNSNode {
  domain: string;
  resolver: string;
  latency: number;
  status: 'TUNNELED' | 'LEAKED' | 'PENDING';
}

const FEATURE_FLAGS: FeatureFlag[] = [
  { flag: "--rotate", cmd: "mac", desc: "Randomize hardware identity", category: "Security" },
  { flag: "--stealth", cmd: "mac", desc: "Mimic generic device OUI", category: "Security" },
  { flag: "--hardened", cmd: "sandbox", desc: "Max isolation parameters", category: "Sandbox" },
  { flag: "--trace", cmd: "sandbox", desc: "Log all IPC transactions", category: "Sandbox" },
  { flag: "--elevated", cmd: "shizuku", desc: "Request root-level binder", category: "System" },
  { flag: "--audit", cmd: "dns", desc: "Run deep DNS leak diagnostics", category: "Network" },
  { flag: "--gh-auth", cmd: "github", desc: "Authorize source access", category: "GitHub" },
  { flag: "--gh-scan", cmd: "github", desc: "Audit repos for secrets", category: "GitHub" },
];

const COMMAND_CATALOG = [
  { cmd: "mac", desc: "Physical address manipulation", flags: ["--rotate", "--stealth", "--vendor"], category: 'Security' },
  { cmd: "sandbox", desc: "Isolated binary containment", flags: ["--init", "--purge", "--hardened", "--trace"], category: 'Sandbox' },
  { cmd: "dns", desc: "Leak protection & routing audit", flags: ["--audit", "--flush", "--harden"], category: 'Network' },
  { cmd: "shizuku", desc: "System-level bridge binder", flags: ["--bind", "--elevated", "--force"], category: 'System' },
  { cmd: "github", desc: "Source control audit bridge", flags: ["--gh-auth", "--gh-scan", "--pull"], category: 'GitHub' },
  { cmd: "audit", desc: "Reputation intel lookup", flags: ["--intel", "--deep", "--global"], category: 'Network' },
];

const categoryStyles: Record<string, string> = {
  System: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  Security: 'text-red-400 bg-red-500/10 border-red-500/20',
  Network: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  Sandbox: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  GitHub: 'text-white bg-slate-500/20 border-white/20',
};

// --- Sub-Components ---

const SystemAlerts = ({ alerts, onDismiss }: { alerts: Alert[], onDismiss: (id: string) => void }) => {
  if (alerts.length === 0) return null;

  return (
    <div className="fixed top-24 left-1/2 -translate-x-1/2 z-[2000] flex flex-col items-center gap-2 pointer-events-none w-full max-w-lg px-6">
      {alerts.map((alert) => (
        <div 
          key={alert.id}
          className={`pointer-events-auto flex items-center gap-4 px-6 py-3 rounded-2xl border backdrop-blur-3xl shadow-2xl animate-in slide-in-from-top-4 duration-300 w-full ${
            alert.type === 'CRITICAL' ? 'bg-red-950/40 border-red-500/50 text-red-100 shadow-red-500/10' :
            alert.type === 'WARNING' ? 'bg-yellow-950/40 border-yellow-500/50 text-yellow-100' :
            alert.type === 'SUCCESS' ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-100' :
            'bg-cyan-950/40 border-cyan-500/50 text-cyan-100'
          }`}
        >
          <div className="shrink-0">
             {alert.type === 'CRITICAL' ? <AlertIcon className="w-5 h-5 text-red-500 animate-pulse" /> :
              alert.type === 'WARNING' ? <AlertIcon className="w-5 h-5 text-yellow-500" /> :
              alert.type === 'SUCCESS' ? <ShieldIcon className="w-5 h-5 text-emerald-500" /> :
              <DirectiveIcon className="w-5 h-5 text-cyan-500" />}
          </div>
          <div className="flex-1 flex flex-col">
            <span className="text-[10px] font-black uppercase tracking-widest opacity-60 mb-0.5">{alert.type} EVENT</span>
            <p className="text-[11px] font-mono leading-tight">{alert.message}</p>
          </div>
          <button 
            onClick={() => onDismiss(alert.id)}
            className="shrink-0 p-1 hover:bg-white/5 rounded-lg transition-colors"
          >
            <CloseIcon className="w-3.5 h-3.5 opacity-50" />
          </button>
        </div>
      ))}
    </div>
  );
};

const PolicyRow = ({ label, active, onToggle }: { label: string, active: boolean, onToggle: () => void }) => (
  <div 
    onClick={onToggle}
    className="flex items-center justify-between p-4 bg-black/40 border border-white/5 rounded-xl hover:bg-white/5 transition-all cursor-pointer group"
  >
    <div className="flex items-center gap-3">
      <div className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-cyan-500 animate-pulse' : 'bg-slate-700'}`}></div>
      <span className="text-[10px] font-black uppercase tracking-tight text-slate-500 group-hover:text-slate-200">{label}</span>
    </div>
    <div className={`w-8 h-4 rounded-full border border-white/10 relative transition-all ${active ? 'bg-cyan-600/20' : 'bg-slate-900'}`}>
       <div className={`absolute top-0.5 w-2.5 h-2.5 rounded-full transition-all ${active ? 'right-0.5 bg-cyan-500' : 'left-0.5 bg-slate-600'}`}></div>
    </div>
  </div>
);

const HUDTile = ({ label, value, color }: { label: string, value: string, color: any }) => {
  const colors: any = {
    blue: 'text-blue-500 bg-blue-500/5 border-blue-500/20',
    green: 'text-green-500 bg-green-500/5 border-green-500/20',
    red: 'text-red-500 bg-red-500/5 border-red-500/20',
    cyan: 'text-cyan-400 bg-cyan-500/5 border-cyan-500/20',
    yellow: 'text-yellow-400 bg-yellow-500/5 border-yellow-500/20',
    purple: 'text-purple-400 bg-purple-500/5 border-purple-500/20',
    white: 'text-white bg-white/5 border-white/20',
  };
  return (
    <div className={`px-4 py-2 rounded-lg border ${colors[color]} backdrop-blur-xl flex flex-col justify-center min-w-[110px]`}>
       <span className="block text-[6px] font-black uppercase tracking-widest mb-0.5 opacity-60">{label}</span>
       <span className="text-sm font-black font-mono tracking-tighter truncate">{value}</span>
    </div>
  );
};

const Panel = ({ title, color, children, icon: Icon, className = "" }: { title: string, color: any, children?: React.ReactNode, icon?: any, className?: string }) => (
  <div className={`bg-[#08090b] border border-white/5 rounded-3xl p-5 shadow-2xl h-full flex flex-col ${className}`}>
     <h3 className={`text-[8px] font-black uppercase tracking-widest mb-3 border-b border-white/5 pb-2 flex items-center justify-between ${color === 'blue' ? 'text-blue-500' : color === 'cyan' ? 'text-cyan-400' : color === 'yellow' ? 'text-yellow-400' : color === 'purple' ? 'text-purple-400' : color === 'red' ? 'text-red-500' : 'text-green-500'}`}>
       <span className="flex items-center gap-2">
         {Icon && <Icon className="w-3 h-3" />}
         {title}
       </span>
       <div className={`w-1 h-1 rounded-full ${color === 'blue' ? 'bg-blue-500' : color === 'cyan' ? 'bg-cyan-400' : color === 'yellow' ? 'bg-yellow-400' : color === 'purple' ? 'bg-purple-400' : color === 'red' ? 'bg-red-500' : 'bg-green-500'} animate-pulse`}></div>
     </h3>
     <div className="flex-1 flex flex-col overflow-hidden">{children}</div>
  </div>
);

const Terminal = ({ onCommand, inputRef, initialInput = "" }: { onCommand: (cmd: string) => Promise<string | undefined | null>, inputRef: React.RefObject<HTMLInputElement>, initialInput?: string }) => {
  const [history, setHistory] = useState<string[]>(["Aegis Root Terminal v6.3.0", "Handshake verified. Node ready.", "Type 'help' for diagnostics."]);
  const [input, setInput] = useState(initialInput);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [history]);

  useEffect(() => {
    if (initialInput) setInput(initialInput);
  }, [initialInput]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    const cmd = input.trim();
    setHistory(prev => [...prev, `root@aegis:~# ${cmd}`]);
    const response = await onCommand(cmd);
    if (response) {
      if (response === 'CLEAR_TERMINAL') {
        setHistory(["Aegis Root Terminal v6.3.0", "Ready."]);
      } else {
        setHistory(prev => [...prev, response]);
      }
    }
    setInput("");
  };

  return (
    <div className="bg-black/90 border border-white/10 rounded-2xl p-4 font-mono text-[9px] h-full flex flex-col shadow-inner relative overflow-hidden">
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-1 custom-scrollbar mb-2 pr-2">
        {history.map((line, i) => (
          <div key={i} className={line.startsWith('root@aegis') ? 'text-cyan-500' : line.includes('ERR') || line.includes('WARNING') ? 'text-red-500' : 'text-slate-400'}>
            {line}
          </div>
        ))}
      </div>
      <form onSubmit={handleSubmit} className="flex gap-2 items-center border-t border-white/5 pt-2">
        <span className="text-cyan-600 font-bold shrink-0">root@aegis:~#</span>
        <input 
          ref={inputRef}
          type="text" 
          value={input} 
          onChange={(e) => setInput(e.target.value)} 
          className="bg-transparent border-none outline-none text-white w-full"
          autoFocus
          spellCheck={false}
        />
      </form>
    </div>
  );
};

const Intercom = ({ systemContext }: { systemContext: string }) => {
  const [active, setActive] = useState(false);
  const [status, setStatus] = useState<'IDLE' | 'CONNECTING' | 'LISTENING' | 'SPEAKING'>('IDLE');
  const sessionRef = useRef<any>(null);
  const audioContextRef = useRef<{ input: AudioContext; output: AudioContext } | null>(null);
  const sourcesRef = useRef<Set<AudioBufferSourceNode>>(new Set());
  const nextStartTimeRef = useRef<number>(0);

  const startBridge = async () => {
    if (active) {
      sessionRef.current?.close();
      setActive(false);
      setStatus('IDLE');
      return;
    }

    setStatus('CONNECTING');
    try {
      const inputCtx = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 16000 });
      const outputCtx = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 24000 });
      audioContextRef.current = { input: inputCtx, output: outputCtx };

      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

      const sessionPromise = ai.live.connect({
        model: 'gemini-2.5-flash-native-audio-preview-12-2025',
        callbacks: {
          onopen: () => {
            setActive(true);
            setStatus('LISTENING');
            const source = inputCtx.createMediaStreamSource(stream);
            const scriptProcessor = inputCtx.createScriptProcessor(4096, 1, 1);
            scriptProcessor.onaudioprocess = (e) => {
              const inputData = e.inputBuffer.getChannelData(0);
              const l = inputData.length;
              const int16 = new Int16Array(l);
              for (let i = 0; i < l; i++) int16[i] = inputData[i] * 32768;
              const pcmBlob = {
                data: encode(new Uint8Array(int16.buffer)),
                mimeType: 'audio/pcm;rate=16000',
              };
              sessionPromise.then(s => s.sendRealtimeInput({ media: pcmBlob }));
            };
            source.connect(scriptProcessor);
            scriptProcessor.connect(inputCtx.destination);
          },
          onmessage: async (msg: LiveServerMessage) => {
            const audioData = msg.serverContent?.modelTurn?.parts[0]?.inlineData?.data;
            if (audioData) {
              setStatus('SPEAKING');
              const { output } = audioContextRef.current!;
              nextStartTimeRef.current = Math.max(nextStartTimeRef.current, output.currentTime);
              const buffer = await decodeAudioData(decode(audioData), output, 24000, 1);
              const source = output.createBufferSource();
              source.buffer = buffer;
              source.connect(output.destination);
              source.onended = () => {
                sourcesRef.current.delete(source);
                if (sourcesRef.current.size === 0) setStatus('LISTENING');
              };
              source.start(nextStartTimeRef.current);
              nextStartTimeRef.current += buffer.duration;
              sourcesRef.current.add(source);
            }
            if (msg.serverContent?.interrupted) {
              sourcesRef.current.forEach(s => s.stop());
              sourcesRef.current.clear();
              nextStartTimeRef.current = 0;
            }
          },
          onclose: () => {
            setActive(false);
            setStatus('IDLE');
          }
        },
        config: {
          responseModalities: [Modality.AUDIO],
          speechConfig: { 
            voiceConfig: { prebuiltVoiceConfig: { voiceName: 'Fenrir' } } 
          },
          systemInstruction: `You are the Aegis Phantom Intercom Security Officer. Your tone is deep, masculine, gravelly, and extremely authoritative.
          Current Device Context: ${systemContext}. Speak directly to the user about their phone's security status. If policies are enabled, explain why with high-gravity detail. 
          Use cybersecurity terminology. Keep responses relatively brief but impactful. Your voice is the final word in system overwatch.`
        }
      });
      sessionRef.current = await sessionPromise;
    } catch (err) {
      console.error("Intercom Bridge Error:", err);
      setStatus('IDLE');
    }
  };

  return (
    <div className={`flex items-center gap-4 px-4 py-2 rounded-xl border transition-all duration-500 ${active ? 'bg-cyan-500/10 border-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.2)]' : 'bg-black/40 border-white/5'}`}>
       <div className="relative w-10 h-10 flex items-center justify-center">
          <div className={`absolute inset-0 rounded-full border border-cyan-500/30 ${active ? 'animate-ping' : ''}`}></div>
          <div className={`w-8 h-8 rounded-full bg-cyan-600/20 flex items-center justify-center border ${status === 'SPEAKING' ? 'border-cyan-400' : 'border-cyan-600/50'}`}>
             <MicIcon className={`w-4 h-4 ${active ? 'text-cyan-400' : 'text-slate-600'}`} />
          </div>
       </div>
       <div className="flex flex-col">
          <span className="text-[7px] font-black uppercase text-slate-500 tracking-widest">Aegis Intercom</span>
          <span className={`text-[9px] font-mono font-bold ${active ? 'text-cyan-400' : 'text-slate-600'}`}>
             {status === 'IDLE' ? 'ENCRYPTED BRIDGE OFF' : status}
          </span>
       </div>
       <button 
         onClick={startBridge}
         className={`ml-2 px-4 py-1 rounded-lg text-[8px] font-black uppercase tracking-tighter transition-all ${active ? 'bg-red-600/20 border border-red-500/50 text-red-500 hover:bg-red-500 hover:text-white' : 'bg-cyan-600/20 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-600 hover:text-white'}`}
       >
          {active ? 'CUT_BRIDGE' : 'ESTABLISH_BRIDGE'}
       </button>
    </div>
  );
};

// --- Main App ---

const App = () => {
  const [isAdmin, setIsAdmin] = useState(false);
  const [showManual, setShowManual] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [blockchain, setBlockchain] = useState<Block[]>([
    { index: 0, timestamp: '10:00:00', data: 'GENESIS_BLOCK', prevHash: '0'.repeat(64), hash: 'ae78...12bc' }
  ]);
  const [telemetryStream, setTelemetryStream] = useState<string[]>([]);
  const terminalInputRef = useRef<HTMLInputElement>(null);
  const [pendingCmd, setPendingCmd] = useState("");
  
  // Sandbox State
  const [sandboxStatus, setSandboxStatus] = useState<SandboxStatus>('IDLE');
  const [sandboxProcesses, setSandboxProcesses] = useState<SandboxProcess[]>([]);

  // DNS State
  const [dnsAuditStatus, setDnsAuditStatus] = useState<DNSAuditStatus>('IDLE');
  const [dnsNodes, setDnsNodes] = useState<DNSNode[]>([]);

  // Shizuku & GitHub State
  const [shizukuStatus, setShizukuStatus] = useState<'IDLE' | 'AUTHORIZING' | 'CONNECTED'>('IDLE');
  const [githubToken, setGithubToken] = useState<string>("");
  const [isGithubAuthorized, setIsGithubAuthorized] = useState(false);

  // Network State
  const [networkIdentity, setNetworkIdentity] = useState({
    mac: '00:1A:2B:3C:4D:5E',
    providerTrust: 98,
  });

  const [activePolicies, setActivePolicies] = useState({
    shizukuBridge: true,
    blockchainLedger: true,
    macRandomization: true,
    providentialAudit: true,
    dnsHardening: true,
    githubBinder: false,
    sandboxIsolation: true,
  });

  const triggerAlert = (type: Alert['type'], message: string) => {
    const id = Math.random().toString(36).substr(2, 9);
    const newAlert = { id, type, message, timestamp: Date.now() };
    setAlerts(prev => [newAlert, ...prev].slice(0, 3));
    setTimeout(() => dismissAlert(id), 6000);
  };

  const dismissAlert = (id: string) => {
    setAlerts(prev => prev.filter(a => a.id !== id));
  };

  const systemContextString = `
    MAC: ${networkIdentity.mac}, 
    ISP Trust: ${networkIdentity.providerTrust}%, 
    GitHub Auth: ${isGithubAuthorized ? 'ACTIVE' : 'NONE'},
    DNS Policy: ${activePolicies.dnsHardening ? 'HARDENED' : 'STANDARD'},
    Sandbox: ${sandboxStatus} with ${sandboxProcesses.length} processes, 
    Policies: ${Object.entries(activePolicies).filter(([_, v]) => v).map(([k]) => k).join(', ')}
  `;

  const runDnsAudit = () => {
    setDnsAuditStatus('TESTING');
    triggerAlert("INFO", "Initiating DNS Leak Diagnostic... checking routing integrity.");
    executeCommand("DNS_AUDIT_START", "TESTING");
    
    const initialNodes: DNSNode[] = [
      { domain: 'google.com', resolver: '...', latency: 0, status: 'PENDING' },
      { domain: 'github.com', resolver: '...', latency: 0, status: 'PENDING' },
      { domain: 'aegis.root', resolver: '...', latency: 0, status: 'PENDING' },
    ];
    setDnsNodes(initialNodes);

    setTimeout(() => {
      const isLeaking = !activePolicies.dnsHardening;
      const resolver = isLeaking ? 'ISP-Default (64.12.1.1)' : 'Aegis-Crypt (1.1.1.1)';
      const finalNodes: DNSNode[] = initialNodes.map(node => ({
        ...node,
        resolver: resolver,
        latency: Math.floor(Math.random() * 40) + 10,
        status: isLeaking ? 'LEAKED' : 'TUNNELED'
      }));
      setDnsNodes(finalNodes);
      setDnsAuditStatus(isLeaking ? 'LEAK_DETECTED' : 'SECURE');
      
      if (isLeaking) {
        triggerAlert("CRITICAL", "DNS LEAK DETECTED: Traffic escaping secure tunnel. ISP-Default nodes identified.");
        executeCommand("DNS_AUDIT_FAIL", "LEAK_FOUND");
      } else {
        triggerAlert("SUCCESS", "DNS Integrity Verified. All requests successfully tunneled via encrypted resolvers.");
        executeCommand("DNS_AUDIT_PASS", "SECURE");
      }
    }, 3000);
  };

  const processTerminalCommand = async (raw: string) => {
    const full = raw.trim().toLowerCase();
    const args = full.split(' ');
    const cmd = args[0];
    const flags = args.slice(1);

    switch(cmd) {
      case 'help':
        executeCommand("TERMINAL_HELP", "SUCCESS");
        return "COMMANDS: mac, sandbox, shizuku, github, dns, audit, clear.";
      case 'clear':
        return "CLEAR_TERMINAL";
      case 'mac':
        if (flags.includes('--rotate')) { rotateMac(flags.includes('--stealth')); return `MAC_SPOOF: Identity cycled.`; }
        break;
      case 'dns':
        if (flags.includes('--audit')) { runDnsAudit(); return "DNS: Audit sequence initiated. Check Overwatch Panel."; }
        if (flags.includes('--harden')) { togglePolicy('dnsHardening'); return `DNS: Hardening ${activePolicies.dnsHardening ? 'disabled' : 'enabled'}.`; }
        break;
      case 'sandbox':
        if (flags.includes('--init')) { initSandbox(flags.includes('--hardened')); return `CONTAINMENT: Isolated cell instantiated.`; }
        if (flags.includes('--purge')) { purgeSandbox(); return "PURGE: Sandbox reset."; }
        break;
      case 'github':
        if (flags.includes('--gh-auth')) { setShowManual(true); return `GITHUB: Authorization manual opened.`; }
        break;
      case 'shizuku':
        if (flags.includes('--bind')) { requestShizukuAuth(flags.includes('--elevated')); return `BRIDGE: Handshake broadcasted.`; }
        break;
      case 'audit':
        if (flags.includes('--intel')) {
            executeCommand("PROVIDER_INTEL_AUDIT", "SUCCESS");
            triggerAlert("SUCCESS", "Network reputation check complete.");
            return `AUDIT: Verified.`;
        }
        break;
      default:
        try {
          const response = await ai.models.generateContent({
            model: 'gemini-3-flash-preview',
            contents: `User command: "${raw}". Response concisely.`,
            config: { systemInstruction: "You are the Aegis Phantom System AI." }
          });
          executeCommand("AI_ANALYSIS", "SUCCESS");
          return response.text;
        } catch (e) {
          executeCommand("TERMINAL_CMD", "WARNING", `Unknown: ${cmd}`);
          return `ERR: Directive '${cmd}' not found.`;
        }
    }
    return `ERR: Parameter mismatch for '${cmd}'.`;
  };

  const initSandbox = (hardened: boolean = false) => {
    setSandboxStatus('ANALYZING');
    setSandboxProcesses([
      { pid: 4410, name: 'threat_agent.bin', risk: hardened ? 2 : 12, status: 'CONTAINED' },
      { pid: 9021, name: 'unknown_ipc.sh', risk: hardened ? 15 : 45, status: 'MONITORING' }
    ]);
    executeCommand("SANDBOX_INIT", hardened ? "HARDENED" : "SUCCESS");
    triggerAlert(hardened ? "SUCCESS" : "INFO", `Sandbox environment instantiated.`);
  };

  const purgeSandbox = () => {
    setSandboxStatus('PURGED');
    setSandboxProcesses([]);
    setTimeout(() => setSandboxStatus('IDLE'), 2000);
    executeCommand("PURGE_SANDBOX", "SUCCESS");
    triggerAlert("WARNING", "Sandbox cell evacuated.");
  };

  const rotateMac = (stealth: boolean = false) => {
    const randomHex = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();
    const prefix = stealth ? "00:E0:4C" : `00:${randomHex()}:${randomHex()}`;
    const newMac = `${prefix}:${randomHex()}:${randomHex()}:${randomHex()}`;
    setNetworkIdentity(prev => ({ ...prev, mac: newMac }));
    executeCommand("MAC_SPOOFED", "SUCCESS");
    triggerAlert("SUCCESS", `Hardware identity cycled.`);
  };

  const executeCommand = (cmdName: string, status: any = 'SUCCESS', reason?: string) => {
    const log = `[${new Date().toLocaleTimeString()}] ${cmdName}: ${status}${reason ? ` (${reason})` : ''}`;
    setTelemetryStream(prev => [log, ...prev].slice(0, 30));
  };

  const togglePolicy = (key: keyof typeof activePolicies) => {
    const nextValue = !activePolicies[key];
    setActivePolicies(prev => ({ ...prev, [key]: nextValue }));
    triggerAlert(nextValue ? "INFO" : "WARNING", `Policy ${String(key).replace(/([A-Z])/g, ' $1')} ${nextValue ? 'engaged' : 'disengaged'}.`);
  };

  const requestShizukuAuth = (elevated: boolean = false) => {
    setShizukuStatus('AUTHORIZING');
    setTimeout(() => {
      setShizukuStatus('CONNECTED');
      executeCommand("SHIZUKU_AUTH", elevated ? "ELEVATED" : "SUCCESS");
      triggerAlert("SUCCESS", `Bridge established.`);
    }, 1500);
  };

  const exportSourcePackage = async () => {
    triggerAlert("INFO", "Bundling Source Overwatch engine...");
    try {
      const zip = new JSZip();
      const indexHtml = document.documentElement.outerHTML;
      const indexTsxResponse = await fetch('index.tsx');
      const indexTsx = await indexTsxResponse.text();
      const metadataJsonResponse = await fetch('metadata.json');
      const metadataJson = await metadataJsonResponse.text();
      zip.file("index.html", indexHtml);
      zip.file("index.tsx", indexTsx);
      zip.file("metadata.json", metadataJson);
      const content = await zip.generateAsync({ type: "blob" });
      const url = URL.createObjectURL(content);
      const link = document.createElement('a');
      link.href = url;
      link.download = `aegis-source-${new Date().getTime()}.zip`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      triggerAlert("SUCCESS", "Extraction complete.");
    } catch (err) {
      triggerAlert("CRITICAL", "Extraction failure.");
    }
  };

  const handleGithubAuth = () => {
    if (githubToken.length < 8) return triggerAlert("WARNING", "Invalid Token.");
    setIsGithubAuthorized(true);
    setActivePolicies(prev => ({ ...prev, githubBinder: true }));
    triggerAlert("SUCCESS", "GitHub Bridge authorized.");
  };

  return (
    <div className="bg-[#020304] text-slate-400 min-h-screen font-sans selection:bg-cyan-500/30 overflow-x-hidden">
      
      <SystemAlerts alerts={alerts} onDismiss={dismissAlert} />

      <nav className="fixed top-0 left-0 w-full z-50 border-b border-white/5 bg-black/90 backdrop-blur-3xl">
        <div className="px-8 py-4 flex justify-between items-center max-w-[1920px] mx-auto">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-4">
               <div className="w-9 h-9 bg-cyan-600 rounded-lg flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.3)]">
                 <ShieldIcon className="w-5 h-5 text-white" />
               </div>
               <div className="flex flex-col">
                  <span className="font-black tracking-[0.3em] text-lg text-white uppercase">Aegis <span className="text-cyan-400 font-light">Phantom</span></span>
                  <span className="text-[6px] font-mono text-cyan-600 tracking-[0.2em] uppercase font-bold">Intercom Bridge v6.3.0</span>
               </div>
            </div>
            <div className="hidden xl:flex border-l border-white/10 pl-8">
               <Intercom systemContext={systemContextString} />
            </div>
          </div>
          <div className="flex items-center gap-3">
             <button onClick={() => setShowManual(true)} className="px-4 py-1.5 rounded-lg text-[7px] font-black tracking-widest uppercase border border-white/10 text-slate-400 hover:text-white transition-all">Manual & Platform Guide</button>
             <button onClick={() => setIsAdmin(!isAdmin)} className={`px-4 py-1.5 rounded-lg text-[7px] font-black tracking-widest uppercase transition-all border ${isAdmin ? 'bg-red-600/10 border-red-600 text-red-500 shadow-lg shadow-red-500/20' : 'bg-white/5 border-white/10 text-slate-500'}`}>
                {isAdmin ? 'ROOT_ACTIVE' : 'SUDO'}
              </button>
          </div>
        </div>
      </nav>

      <main className="pt-24 px-6 pb-6 max-w-[1920px] mx-auto grid grid-cols-1 xl:grid-cols-12 gap-6">
        
        <div className="xl:col-span-9 grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8 h-[400px]">
             <Panel title="Secure Root Shell" color="cyan" icon={DirectiveIcon}>
                <Terminal onCommand={processTerminalCommand} inputRef={terminalInputRef} initialInput={pendingCmd} />
             </Panel>
          </div>

          <div className="lg:col-span-4 h-[400px]">
             <Panel title="Sandbox Cell" color="yellow" icon={SystemIcon}>
                <div className="flex-1 flex flex-col">
                   <div className={`p-3 rounded-lg border mb-3 flex justify-between items-center ${sandboxStatus === 'ANALYZING' ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-black/40 border-white/5'}`}>
                      <span className="text-[8px] font-black uppercase text-slate-400 tracking-widest">Containment</span>
                      <span className={`text-[8px] font-mono font-bold ${sandboxStatus === 'ANALYZING' ? 'text-yellow-500 animate-pulse' : 'text-slate-600'}`}>{sandboxStatus}</span>
                   </div>
                   <div className="flex-1 overflow-y-auto space-y-2 custom-scrollbar pr-1">
                      {sandboxProcesses.length > 0 ? sandboxProcesses.map(p => (
                        <div key={p.pid} className="p-2.5 bg-white/5 border border-white/5 rounded-lg flex justify-between items-center hover:bg-white/10 transition-all">
                           <div><p className="text-[8px] font-black text-white">{p.name}</p><p className="text-[6px] text-slate-500 font-mono">PID:{p.pid}</p></div>
                           <span className={`text-[7px] font-black px-1.5 py-0.5 rounded border ${p.risk > 40 ? 'text-red-500 border-red-500/30' : 'text-green-500 border-green-500/30'}`}>{p.risk}% RISK</span>
                        </div>
                      )) : <div className="h-full flex items-center justify-center text-slate-800 font-mono text-[8px] uppercase tracking-widest italic opacity-40">Cell Vacant</div>}
                   </div>
                   <div className="grid grid-cols-2 gap-2 mt-3">
                      <button onClick={() => initSandbox(false)} className="py-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-[7px] font-black uppercase text-yellow-500 hover:bg-yellow-500 transition-all">Init Cell</button>
                      <button onClick={purgeSandbox} className="py-2 bg-white/5 border border-white/10 rounded-lg text-[7px] font-black uppercase text-slate-400 hover:text-white transition-all">Purge</button>
                   </div>
                </div>
             </Panel>
          </div>

          <div className="lg:col-span-7 h-[360px]">
             <Panel title="Network & DNS Overwatch" color="red" icon={ShieldIcon}>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5 h-full">
                   <div className="space-y-3">
                      <HUDTile label="MAC Identity" value={networkIdentity.mac} color="red" />
                      <div className={`p-4 rounded-xl border flex flex-col gap-2 transition-all ${dnsAuditStatus === 'LEAK_DETECTED' ? 'bg-red-500/10 border-red-500/30' : dnsAuditStatus === 'SECURE' ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-black/40 border-white/5'}`}>
                         <div className="flex justify-between items-center">
                            <span className="text-[7px] font-black uppercase text-slate-500 tracking-widest">DNS Leak Status</span>
                            <span className={`text-[8px] font-mono font-bold ${dnsAuditStatus === 'LEAK_DETECTED' ? 'text-red-500' : dnsAuditStatus === 'SECURE' ? 'text-emerald-500' : 'text-slate-600'}`}>
                               {dnsAuditStatus === 'IDLE' ? 'AWAITING_AUDIT' : dnsAuditStatus}
                            </span>
                         </div>
                         <button 
                           onClick={runDnsAudit} 
                           disabled={dnsAuditStatus === 'TESTING'}
                           className={`w-full py-1.5 rounded text-[8px] font-black uppercase transition-all ${dnsAuditStatus === 'TESTING' ? 'bg-white/5 text-slate-700' : 'bg-cyan-600/20 text-cyan-400 hover:bg-cyan-500 hover:text-white border border-cyan-500/30'}`}
                         >
                            {dnsAuditStatus === 'TESTING' ? 'AUDITING...' : 'Perform Leak Test'}
                         </button>
                      </div>
                      <HUDTile label="Reputation Index" value={`${networkIdentity.providerTrust}%`} color="green" />
                   </div>
                   <div className="flex flex-col gap-2 h-full">
                      <h4 className="text-[7px] font-black uppercase text-slate-500 tracking-widest border-b border-white/5 pb-1">Resolution Diagnostics</h4>
                      <div className="flex-1 overflow-y-auto space-y-1.5 custom-scrollbar pr-1">
                         {dnsNodes.length > 0 ? dnsNodes.map((node, i) => (
                           <div key={i} className="p-2 bg-white/5 border border-white/5 rounded-lg flex flex-col gap-1">
                              <div className="flex justify-between items-center">
                                 <span className="text-[8px] font-mono text-white">{node.domain}</span>
                                 <span className={`text-[6px] font-black px-1 rounded ${node.status === 'TUNNELED' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-red-500/20 text-red-500'}`}>
                                    {node.status}
                                 </span>
                              </div>
                              <div className="flex justify-between items-center text-[7px] text-slate-500 font-mono">
                                 <span>{node.resolver}</span>
                                 <span>{node.latency}ms</span>
                              </div>
                           </div>
                         )) : <div className="h-full flex items-center justify-center text-slate-800 text-[8px] italic opacity-40">No diagnostic data.</div>}
                      </div>
                   </div>
                </div>
             </Panel>
          </div>

          <div className="lg:col-span-5 h-[360px]">
             <Panel title="System Logic Stream" color="green" icon={NetworkIcon}>
                <div className="flex-1 overflow-y-auto space-y-1.5 font-mono text-[7px] custom-scrollbar pr-2">
                   {telemetryStream.length > 0 ? telemetryStream.map((log, i) => (
                      <div key={i} className="flex gap-3 hover:text-green-400 transition-colors border-l border-white/10 pl-2 py-0.5">
                         <span className="text-slate-600 shrink-0">[{log.split('] ')[0].replace('[', '')}]</span>
                         <span className="text-slate-400 leading-tight">{log.split('] ')[1]}</span>
                      </div>
                   )) : <div className="text-slate-800 italic uppercase">Initializing bridge...</div>}
                </div>
             </Panel>
          </div>
        </div>

        <div className="xl:col-span-3 space-y-6">
           <Panel title="Featured Flags Directory" color="cyan" icon={DirectiveIcon}>
              <div className="grid grid-cols-1 gap-2 overflow-y-auto max-h-[250px] pr-1 custom-scrollbar">
                 {FEATURE_FLAGS.map((f, i) => (
                    <div key={i} onClick={() => setPendingCmd(`${f.cmd} ${f.flag}`)} className="p-2.5 bg-black/40 border border-white/5 rounded-xl hover:border-cyan-500/40 transition-all cursor-pointer group">
                       <div className="flex justify-between items-center mb-1">
                          <span className="text-[8px] font-mono text-cyan-400 font-bold">{f.flag}</span>
                          <span className="text-[6px] px-1 py-0.5 bg-cyan-900/20 border border-cyan-800/30 text-cyan-600 rounded uppercase">{f.cmd}</span>
                       </div>
                       <p className="text-[7px] text-slate-500 leading-tight">{f.desc}</p>
                    </div>
                 ))}
              </div>
           </Panel>

           <div className="bg-[#08090b] border border-white/5 rounded-3xl p-4 shadow-2xl">
              <h2 className="text-[8px] font-black text-white uppercase mb-4 border-b border-white/5 pb-3 tracking-widest">Active Policies</h2>
              <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-1 custom-scrollbar">
                 <PolicyRow label="DNS Hardening" active={activePolicies.dnsHardening} onToggle={() => togglePolicy('dnsHardening')} />
                 <PolicyRow label="GitHub Source Binder" active={activePolicies.githubBinder} onToggle={() => togglePolicy('githubBinder')} />
                 <PolicyRow label="Sandbox Isolation" active={activePolicies.sandboxIsolation} onToggle={() => togglePolicy('sandboxIsolation')} />
                 <PolicyRow label="MAC Randomization" active={activePolicies.macRandomization} onToggle={() => togglePolicy('macRandomization')} />
              </div>
           </div>
        </div>
      </main>

      {showManual && (
        <div className="fixed inset-0 z-[1000] flex items-center justify-center p-6 bg-black/95 backdrop-blur-3xl animate-in fade-in duration-300">
           <div className="bg-[#08090b] border border-white/10 w-full max-w-2xl p-8 rounded-[2rem] shadow-2xl relative overflow-hidden flex flex-col max-h-[85vh]">
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyan-500 to-transparent"></div>
              <button onClick={() => setShowManual(false)} className="absolute top-6 right-8 text-slate-600 hover:text-white text-xl transition-colors">×</button>
              
              <div className="flex items-center gap-5 mb-8">
                 <div className="w-14 h-14 bg-cyan-700 rounded-xl flex items-center justify-center">
                    <ShieldIcon className="w-7 h-7 text-white" />
                 </div>
                 <div>
                    <h2 className="text-2xl font-black text-white tracking-tighter uppercase leading-none">Aegis Tactical Manual</h2>
                    <p className="text-cyan-500 uppercase tracking-[0.2em] font-mono text-[9px] font-bold">Integration Guide v6.3.0</p>
                 </div>
              </div>

              <div className="flex-1 overflow-y-auto pr-3 custom-scrollbar space-y-8">
                 
                 <section className="space-y-4 p-5 bg-blue-500/5 border border-blue-500/20 rounded-2xl">
                    <h3 className="text-base font-black text-blue-400 flex items-center gap-2 font-mono uppercase"><NetworkIcon className="w-4 h-4" /> DNS Integrity Hub</h3>
                    <p className="text-[10px] text-slate-400 leading-relaxed">Engage <span className="text-white font-bold">DNS Hardening</span> to force all resolution through encrypted tactical nodes. Use `dns --audit` to check for leaking requests that bypass the secure tunnel.</p>
                 </section>

                 <section className="space-y-4 p-5 bg-white/5 border border-white/10 rounded-2xl">
                    <div className="flex justify-between items-center">
                       <h3 className="text-base font-black text-white flex items-center gap-2 font-mono uppercase"><GithubIcon className="w-4 h-4" /> GitHub Binder</h3>
                       <div className="flex items-center gap-2">
                          <input type="password" placeholder="PAT..." value={githubToken} onChange={(e) => setGithubToken(e.target.value)} className="bg-black border border-white/10 rounded px-3 py-1 text-[9px] font-mono text-cyan-400 outline-none w-32" />
                          <button onClick={handleGithubAuth} className="bg-white/10 text-white px-3 py-1 rounded text-[8px] font-black uppercase">Auth</button>
                       </div>
                    </div>
                 </section>

                 <section className="space-y-6">
                    <h3 className="text-lg font-black text-white border-b border-white/10 pb-2 uppercase tracking-tight">Platform Interaction Guide</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                       <div className="p-4 bg-slate-900/50 border border-white/5 rounded-xl space-y-2">
                          <h4 className="text-[10px] font-black text-cyan-400 uppercase flex items-center gap-2"><AppleIcon className="w-3.5 h-3.5" /> iOS / Safari</h4>
                          <p className="text-[9px] leading-relaxed text-slate-400">Add to Home Screen as PWA. Use Siri Shortcuts to trigger 'dns --audit' remotely via the Aegis Bridge.</p>
                       </div>
                       <div className="p-4 bg-slate-900/50 border border-white/5 rounded-xl space-y-2">
                          <h4 className="text-[10px] font-black text-green-500 uppercase flex items-center gap-2"><AndroidIcon className="w-3.5 h-3.5" /> Android / Samsung</h4>
                          <p className="text-[9px] leading-relaxed text-slate-400">Enable <span className="text-white">Shizuku</span> for deep packet inspection. Samsung users should run Aegis in <span className="text-white">Knox Secure Folders</span>.</p>
                       </div>
                       <div className="p-4 bg-slate-900/50 border border-white/5 rounded-xl space-y-2">
                          <h4 className="text-[10px] font-black text-yellow-500 uppercase flex items-center gap-2"><AmazonIcon className="w-3.5 h-3.5" /> Amazon Echo</h4>
                          <p className="text-[9px] leading-relaxed text-slate-400">Invoke "Alexa, start Aegis Bridge" to broadcast security alerts through your smart home network nodes.</p>
                       </div>
                       <div className="p-4 bg-slate-900/50 border border-white/5 rounded-xl space-y-2">
                          <h4 className="text-[10px] font-black text-blue-500 uppercase flex items-center gap-2"><DownloadIcon className="w-3.5 h-3.5" /> Source Bundle</h4>
                          <button onClick={exportSourcePackage} className="w-full mt-1 bg-blue-600/20 text-blue-400 border border-blue-500/30 py-2 rounded-lg text-[8px] font-black uppercase transition-all tracking-widest">Bundle Project</button>
                       </div>
                    </div>
                 </section>
              </div>

              <div className="pt-6 mt-4 border-t border-white/5 flex justify-end">
                 <button onClick={() => setShowManual(false)} className="px-8 py-3 bg-cyan-600 rounded-xl text-[10px] font-black tracking-widest uppercase text-white hover:scale-105 transition-all">Acknowledge Directive</button>
              </div>
           </div>
        </div>
      )}
    </div>
  );
};

// --- Icons ---
const ShieldIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const AlertIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);
const NetworkIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
    <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
  </svg>
);
const SystemIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
    <circle cx="12" cy="12" r="4"/>
  </svg>
);
const DirectiveIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
  </svg>
);
const MicIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
    <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
    <line x1="12" y1="19" x2="12" y2="23"/>
    <line x1="8" y1="23" x2="16" y2="23"/>
  </svg>
);
const CloseIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);
const DownloadIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
  </svg>
);
const GithubIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
  </svg>
);
const AppleIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 20.94c1.88 0 3.05-1.12 3.05-1.12s-1.05-.12-1.95-1.32c-.88-1.16-.72-2.38-.72-2.38s1.42-.3 2.52.88c.98 1.05 1.42 2.22 1.42 2.22s1.44-.92 1.88-2.68c.42-1.68-.18-3.48-1.22-4.68-1.05-1.22-2.65-1.85-4.12-1.85-1.68 0-3.12.72-4.12 1.85-1.05 1.22-1.65 3-1.22 4.68.45 1.78 1.88 2.68 1.88 2.68s.45-1.18 1.42-2.22c1.1-1.18 2.52-.88 2.52-.88s.15 1.22-.72 2.38c-.9 1.2-1.95 1.32-1.95 1.32s1.18 1.12 3.05 1.12z"/>
    <path d="M12 8.35c.18-1.82 1.58-3.25 3.25-3.25 0 1.68-1.42 3.25-3.25 3.25z"/>
  </svg>
);
const AndroidIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 18V22"/><path d="M8 18V22"/><path d="M16 18V22"/><path d="M3.5 10.5C3.5 6.36 6.36 3.5 10.5 3.5S17.5 6.36 17.5 10.5V14.5C17.5 15.6 16.6 16.5 15.5 16.5H5.5C4.4 16.5 3.5 15.6 3.5 14.5V10.5Z"/>
    <path d="M6.5 3.5L4.5 1.5"/><path d="M14.5 3.5L16.5 1.5"/><circle cx="7.5" cy="10.5" r="1"/><circle cx="13.5" cy="10.5" r="1"/>
  </svg>
);
const AmazonIcon = (props: any) => (
  <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/><path d="M12 8v4l3 3"/>
  </svg>
);

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
