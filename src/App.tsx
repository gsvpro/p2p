import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Send, 
  User, 
  Terminal, 
  Lock, 
  Clock, 
  Paperclip,
  Trash2,
  Search,
  Smile,
  File as FileIcon,
  Download,
  RefreshCw
} from 'lucide-react';
import EmojiPicker, { EmojiClickData } from 'emoji-picker-react';
import { iroh } from './lib/iroh';
import { SecureMessage, Identity, FileTransfer } from './types';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { format } from 'date-fns';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function App() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [messages, setMessages] = useState<SecureMessage[]>([]);
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [peers, setPeers] = useState<string[]>([]);
  const [transfers, setTransfers] = useState<FileTransfer[]>([]);
  const [newPeerId, setNewPeerId] = useState('');
  const [inputText, setInputText] = useState('');
  const [isEphemeral, setIsEphemeral] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
  const [showEmojiPicker, setShowEmojiPicker] = useState<string | null>(null);
  const [mobilePanel, setMobilePanel] = useState<'peers' | 'chat' | 'metrics'>('chat');
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const init = async () => {
      const name = localStorage.getItem('nexus_name') || `Node_${Math.floor(Math.random() * 999)}`;
      await iroh.initialize(name);
      setIdentity(iroh.getIdentity());
      setIsInitialized(true);
    };
    init();
  }, []);

  useEffect(() => {
    iroh.onMessage((msg) => {
      if (msg.type === 'reaction') {
        setMessages(prev => prev.map(m => {
          if (m.id === msg.targetMessageId) {
            const reactions = { ...m.reactions };
            const users = reactions[msg.content] || [];
            if (!users.includes(msg.senderId)) {
              reactions[msg.content] = [...users, msg.senderId];
            }
            return { ...m, reactions };
          }
          return m;
        }));
      } else {
        setMessages(prev => [...prev, msg]);
      }
      setPeers(prev => prev.includes(msg.senderId) ? prev : [...prev, msg.senderId]);
    });

    iroh.onTransferUpdate((newTransfers) => {
      setTransfers(newTransfers);
    });

    const interval = setInterval(() => {
      setPeers(iroh.getConnectedPeers());
      setMessages(prev => prev.filter(m => !m.expiresAt || m.expiresAt > Date.now()));
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, activePeer]);

  const handleConnect = async () => {
    if (newPeerId.trim()) {
      await iroh.connectByTicket(newPeerId.trim());
      setActivePeer(newPeerId.trim());
      setNewPeerId('');
    }
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!inputText.trim() || !activePeer) return;

    const sentMsg = await iroh.sendMessage(activePeer, inputText, { ephemeral: isEphemeral });
    if (sentMsg) {
      setMessages(prev => [...prev, sentMsg]);
      setInputText('');
    }
  };

  const handleFileShare = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && activePeer) {
      await iroh.sendFile(activePeer, file);
    }
  };

  const handleReaction = async (messageId: string, emoji: string) => {
    if (!activePeer) return;
    const reactionMsg = await iroh.sendReaction(activePeer, messageId, emoji);
    if (reactionMsg) {
      setMessages(prev => prev.map(m => {
        if (m.id === messageId) {
          const reactions = { ...m.reactions };
          const users = reactions[emoji] || [];
          if (!users.includes(identity?.id || '')) {
            reactions[emoji] = [...users, identity?.id || ''];
          }
          return { ...m, reactions };
        }
        return m;
      }));
    }
    setShowEmojiPicker(null);
  };

  if (!isInitialized) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-black">
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center gap-4"
        >
          <Terminal className="w-12 h-12 text-brand animate-pulse" />
          <p className="text-brand font-mono text-sm tracking-widest uppercase">Initializing Iroh Node...</p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-bg text-text-primary overflow-hidden font-sans">
      <input 
        type="file" 
        className="hidden" 
        ref={fileInputRef} 
        onChange={handleFileShare}
      />
      {/* Top Navigation / Title Bar */}
      <nav className="h-12 bg-surface-rail border-b border-border flex items-center justify-between px-4 flex-shrink-0 z-20">
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setMobilePanel(mobilePanel === 'peers' ? 'chat' : 'peers')}
            className="md:hidden p-1.5 hover:bg-white/5 rounded transition-colors"
          >
            <Search className="w-4 h-4 text-brand" />
          </button>
          <div className="w-3 h-3 bg-brand rounded-full shadow-[0_0_8px_#00FF41] hidden xs:block"></div>
          <span className="font-mono text-[10px] tracking-widest text-brand uppercase font-bold truncate max-w-[100px] xs:max-w-none">NODE_ACTIVE // PQ-TUNNEL</span>
        </div>
        <div className="flex items-center gap-2 xs:gap-6">
          <div className="hidden sm:flex items-center gap-2">
            <span className="text-[9px] uppercase tracking-tighter opacity-50 font-bold">Node ID</span>
            <span className="font-mono text-xs text-text-secondary">{identity?.id.slice(0, 8)}...</span>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setMobilePanel(mobilePanel === 'metrics' ? 'chat' : 'metrics')}
              className="md:hidden p-1.5 hover:bg-white/5 rounded transition-colors"
            >
              <RefreshCw className="w-4 h-4 text-brand" />
            </button>
            <button className="bg-border hover:bg-gray-700 px-2 xs:px-3 py-1 rounded text-[10px] uppercase font-bold transition-colors">Settings</button>
          </div>
        </div>
      </nav>

      <div className="flex flex-1 overflow-hidden relative">
        {/* Sidebar: Contacts & Channels */}
        <aside className={cn(
          "w-64 bg-surface-sidebar border-r border-border flex flex-col flex-shrink-0 transition-transform duration-300 z-30",
          "absolute inset-y-0 left-0 md:relative md:translate-x-0",
          mobilePanel === 'peers' ? "translate-x-0 shadow-2xl" : "-translate-x-full"
        )}>
          <div className="p-4 border-b border-border">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[11px] font-bold uppercase tracking-widest opacity-40">Peers</h2>
              <button 
                onClick={() => {
                  const id = prompt("Enter Node Ticket:");
                  if (id) {
                    setNewPeerId(id);
                    handleConnect();
                  }
                }}
                className="text-brand text-lg hover:opacity-80 transition-opacity"
              >
                +
              </button>
            </div>
            
            <div className="space-y-1">
              <div className="relative mb-3">
                <input 
                  type="text" 
                  placeholder="Seach tickets..."
                  className="w-full bg-bg border border-border rounded py-1.5 pl-3 pr-3 text-[10px] focus:border-brand/40 outline-none"
                  value={newPeerId}
                  onChange={(e) => setNewPeerId(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleConnect()}
                />
              </div>

              {peers.length === 0 && (
                <div className="py-8 text-center px-4">
                  <p className="text-[10px] text-text-secondary uppercase tracking-tight italic">No active iroh mesh. Connect to a peer ticket.</p>
                </div>
              )}

              {peers.map(peerId => (
                <div 
                  key={peerId}
                  onClick={() => setActivePeer(peerId)}
                  className={cn(
                    "flex items-center gap-3 p-2 rounded-md cursor-pointer transition-all group",
                    activePeer === peerId ? "bg-[#1C1F26] border-l-2 border-brand" : "hover:bg-surface-rail"
                  )}
                >
                  <div className="w-8 h-8 rounded bg-gradient-to-br from-gray-700 to-gray-900 flex items-center justify-center font-bold text-[10px] border border-border">
                    {peerId.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="flex-1 overflow-hidden">
                    <div className="text-xs font-semibold truncate group-hover:text-brand transition-colors">Node_{peerId.slice(0, 4)}</div>
                    <div className="text-[10px] opacity-40 truncate italic">{peerId}</div>
                  </div>
                  {activePeer === peerId && <div className="w-1.5 h-1.5 bg-brand rounded-full"></div>}
                </div>
              ))}
            </div>
          </div>

          <div className="p-4 flex-1 overflow-y-auto terminal-scroll">
            <h2 className="text-[11px] font-bold uppercase tracking-widest opacity-40 mb-3">Payload Transfers</h2>
            <div className="space-y-3">
              {transfers.map(t => (
                <div key={t.id} className="p-3 bg-surface-rail rounded border border-border">
                  <div className="flex justify-between text-[9px] mb-1 font-bold uppercase">
                    <span className="truncate max-w-[100px]">{t.name}</span>
                    <span className={t.status === 'completed' ? 'text-brand' : 'text-blue-400'}>
                      {t.status === 'completed' ? 'DONE' : `${Math.round((t.progress / t.size) * 100)}%`}
                    </span>
                  </div>
                  <div className="w-full bg-bg h-1 rounded-full overflow-hidden mb-1">
                    <div 
                      className={cn("h-1 rounded-full transition-all duration-300", t.status === 'completed' ? 'bg-brand' : 'bg-blue-400')}
                      style={{ width: `${(t.progress / t.size) * 100}%` }}
                    ></div>
                  </div>
                  <div className="flex justify-between items-center text-[8px] opacity-40 uppercase tracking-tighter">
                    <div className="flex gap-2">
                       <span>{t.type}</span>
                       <span>{(t.size / 1024).toFixed(1)} KB</span>
                    </div>
                    {t.downloadUrl && (
                      <a 
                        href={t.downloadUrl} 
                        download={t.name}
                        className="text-brand hover:underline flex items-center gap-0.5"
                      >
                        <Download className="w-2 h-2" /> DL
                      </a>
                    )}
                  </div>
                </div>
              ))}
              {transfers.length === 0 && (
                <div className="p-2 opacity-40 grayscale italic text-[10px] text-center border border-dashed border-border rounded">
                  No active mesh uploads
                </div>
              )}
            </div>
          </div>
        </aside>

        {/* Main Chat Area */}
        <main className={cn(
          "flex-1 flex flex-col bg-bg relative overflow-hidden transition-opacity duration-300",
          mobilePanel !== 'chat' ? "opacity-30 pointer-events-none md:opacity-100 md:pointer-events-auto" : "opacity-100"
        )}>
          {mobilePanel !== 'chat' && (
            <div 
              className="absolute inset-0 z-40 md:hidden" 
              onClick={() => setMobilePanel('chat')}
            />
          )}
          {!activePeer ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <Shield className="w-12 h-12 text-border mb-4 opacity-20" />
              <h2 className="text-sm font-bold opacity-30 uppercase tracking-[0.2em]">Iroh Isolated</h2>
              <p className="text-[11px] text-text-secondary mt-2 max-w-xs leading-relaxed uppercase tracking-tighter">
                Enter an Iroh ticket to establish a document sync tunnel.
              </p>
            </div>
          ) : (
            <>
              <header className="h-14 border-b border-border flex items-center justify-between px-6 bg-bg">
                <div className="flex items-center gap-3">
                  <h1 className="font-bold text-sm">Node_{activePeer.slice(0, 4)}</h1>
                  <span className="px-2 py-0.5 rounded bg-surface-rail text-[9px] text-brand border border-brand/20 font-bold uppercase tracking-widest">PQXDH_TUNNEL</span>
                </div>
                <div className="flex items-center gap-4 text-[10px] opacity-60 font-bold uppercase">
                  <span className="flex items-center gap-1 text-brand/80"><Shield className="w-3 h-3" /> QUANTUM_SAFE</span>
                  <div className="w-px h-3 bg-border"></div>
                  <span className={cn(
                    "flex items-center gap-1",
                    isEphemeral ? "text-orange-400" : "text-gray-500"
                  )}>
                    <Clock className="w-3 h-3" /> Ephemeral {isEphemeral ? 'Active' : 'Off'}
                  </span>
                </div>
              </header>

              <div 
                ref={scrollRef}
                className="flex-1 p-6 space-y-6 overflow-y-auto terminal-scroll scroll-smooth"
              >
                {messages.filter(m => m.senderId === activePeer || m.receiverId === activePeer).map((msg) => (
                  <div 
                    key={msg.id}
                    className={cn(
                      "flex gap-4 max-w-2xl group",
                      msg.senderId === identity?.id ? "ml-auto flex-row-reverse" : ""
                    )}
                  >
                    <div className={cn(
                      "w-8 h-8 rounded-full flex-shrink-0 flex items-center justify-center text-[10px] font-bold border border-border",
                      msg.senderId === identity?.id ? "bg-gray-700" : "bg-blue-600"
                    )}>
                      {msg.senderId === identity?.id ? 'U' : 'P'}
                    </div>
                    <div className={cn(
                      "space-y-1",
                      msg.senderId === identity?.id ? "text-right" : ""
                    )}>
                      <div className={cn(
                        "flex items-baseline gap-2",
                        msg.senderId === identity?.id ? "flex-row-reverse" : ""
                      )}>
                        <span className="text-[10px] font-bold uppercase opacity-80 decoration-brand group-hover:underline cursor-default">
                          {msg.senderId === identity?.id ? 'Identity_Local' : `Node_${msg.senderId.slice(0, 4)}`}
                        </span>
                        <span className="text-[10px] opacity-30 font-mono">
                          {format(msg.timestamp, 'HH:mm:ss')}
                        </span>
                      </div>
                      <div className="relative">
                        <div className={cn(
                          "p-3 rounded-xl text-sm border transition-all",
                          msg.senderId === identity?.id 
                            ? "bg-brand text-black font-semibold border-brand rounded-tr-none" 
                            : "bg-surface-rail border-border text-text-primary rounded-tl-none"
                        )}>
                          {msg.content}
                        </div>
                        
                        {/* Reactions Display */}
                        {msg.reactions && Object.keys(msg.reactions).length > 0 && (
                          <div className={cn(
                            "flex gap-1 mt-1",
                            msg.senderId === identity?.id ? "justify-end" : "justify-start"
                          )}>
                            {(Object.entries(msg.reactions) as [string, string[]][]).map(([emoji, users]) => (
                              <div key={emoji} className="bg-bg border border-border px-1.5 py-0.5 rounded-full text-[10px] flex items-center gap-1 shadow-sm">
                                <span>{emoji}</span>
                                <span className="opacity-50">{users.length}</span>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Reaction Picker Trigger */}
                        <div className={cn(
                          "absolute top-0 opacity-0 group-hover:opacity-100 transition-opacity",
                          msg.senderId === identity?.id ? "right-full mr-2" : "left-full ml-2"
                        )}>
                          <button 
                            onClick={() => setShowEmojiPicker(msg.id)}
                            className="p-1.5 bg-surface-rail border border-border rounded-lg text-text-secondary hover:text-brand"
                          >
                            <Smile className="w-4 h-4" />
                          </button>
                          {showEmojiPicker === msg.id && (
                            <div className="absolute top-8 z-50 shadow-2xl">
                              <EmojiPicker 
                                onEmojiClick={(emoji: EmojiClickData) => handleReaction(msg.id, emoji.emoji)}
                                width={250}
                                height={300}
                                theme={"dark" as any}
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Input Bar */}
              <footer className="p-4 bg-surface-sidebar border-t border-border">
                <div className="relative flex items-center bg-bg border border-border rounded-lg px-3 xs:px-4 py-2 focus-within:border-brand/40 transition-colors shadow-inner">
                  <button 
                    onClick={() => fileInputRef.current?.click()}
                    className="text-text-secondary hover:text-white mr-2 xs:mr-3 transition-colors group"
                  >
                    <Paperclip className="w-5 h-5 group-hover:text-brand" />
                  </button>
                  <input 
                    type="text" 
                    placeholder="Message..." 
                    className="bg-transparent flex-1 outline-none text-xs xs:text-sm placeholder-gray-700 font-mono w-0"
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        handleSendMessage();
                      }
                    }}
                  />
                  <div className="flex items-center gap-1.5 xs:gap-3">
                    <button 
                      onClick={() => setIsEphemeral(!isEphemeral)}
                      className={cn(
                        "text-[8px] xs:text-[9px] font-mono font-bold px-1.5 xs:px-2 py-1 rounded transition-colors uppercase",
                        isEphemeral ? "text-orange-400 bg-orange-400/10" : "text-brand/50 bg-brand/5"
                      )}
                    >
                      {isEphemeral ? 'EPH' : 'STD'}
                    </button>
                    <button 
                      onClick={handleSendMessage}
                      disabled={!inputText.trim()}
                      className="bg-brand text-black w-7 h-7 xs:w-8 xs:h-8 rounded flex items-center justify-center hover:opacity-90 active:scale-95 disabled:opacity-30 transition-all shadow-[0_0_10px_rgba(0,255,65,0.4)]"
                    >
                      <Send className="w-3.5 h-3.5 xs:w-4 xs:h-4" />
                    </button>
                  </div>
                </div>
              </footer>
            </>
          )}
        </main>

        {/* Right Rail: Node Details */}
        <aside className={cn(
          "w-72 bg-surface-rail border-l border-border p-5 flex flex-col gap-6 overflow-hidden transition-transform duration-300 z-30",
          "absolute inset-y-0 right-0 md:relative md:translate-x-0",
          mobilePanel === 'metrics' ? "translate-x-0 shadow-2xl" : "translate-x-full"
        )}>
          <section>
            <h3 className="text-[10px] font-bold uppercase tracking-widest opacity-40 mb-4">Post-Quantum Node</h3>
            <div className="space-y-4">
              <div className="p-3 bg-brand/5 rounded border border-brand/20">
                <div className="text-[9px] text-brand mb-1 uppercase font-bold tracking-widest flex items-center gap-2">
                  <Shield className="w-3 h-3" /> Quantum Status
                </div>
                <div className="text-[11px] font-bold text-brand">Hybrid ML-KEM + P-256</div>
                <div className="text-[9px] opacity-60 mt-1 font-mono leading-tight">
                  Status: ARMORED<br/>
                  Engine: crystals-kyber-js
                </div>
              </div>
              <div>
                <div className="text-[9px] opacity-30 mb-1 font-mono uppercase font-bold tracking-widest">Classical PK</div>
                <div className="font-mono text-[9px] break-all text-text-secondary bg-bg p-2 rounded border border-border/50">
                  {identity?.classicalPublicKey.slice(0, 48)}...
                </div>
              </div>
              <div>
                <div className="text-[9px] opacity-30 mb-1 font-mono uppercase font-bold tracking-widest">Quantum PK</div>
                <div className="font-mono text-[9px] break-all text-text-secondary bg-bg p-2 rounded border border-border/50">
                  {identity?.pqcPublicKey.slice(0, 48)}...
                </div>
              </div>
              <div>
                <div className="text-[9px] opacity-30 mb-1 font-mono uppercase font-bold tracking-widest">Node Ticket</div>
                <div 
                  className="font-mono text-[9px] break-all text-brand bg-bg p-2 rounded border border-border/50 cursor-pointer hover:bg-brand/5"
                  onClick={() => navigator.clipboard.writeText(identity?.id || '')}
                >
                  {identity?.id}
                </div>
              </div>
              <div className="p-3 bg-bg/50 rounded border border-border border-dashed">
                <div className="text-[9px] opacity-30 mb-2 uppercase font-bold">Document Sync</div>
                <div className="text-[11px] font-bold flex items-center gap-2">
                  <RefreshCw className="w-3 h-3 text-brand animate-spin" />
                  REAL_TIME_ORBIT
                </div>
                <div className="text-[10px] text-text-secondary mt-1 font-mono leading-tight">
                  Status: Synchronizing<br/>
                  ALPN: iroh_hybrid/1
                </div>
              </div>
            </div>
          </section>

          <section className="mt-auto">
            <div className="p-4 bg-surface-sidebar rounded border border-border relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-32 h-32 bg-brand/5 rounded-full -mr-16 -mt-16 group-hover:bg-brand/10 transition-colors"></div>
              <div className="relative z-10">
                <h4 className="text-[10px] font-bold uppercase opacity-40 mb-3 tracking-widest">Protocol Metrics</h4>
                <div className="space-y-2">
                  <div className="flex justify-between text-[10px] font-mono">
                    <span className="opacity-50">SYNC_SPEED</span>
                    <span className="text-brand">64.1 KB/s</span>
                  </div>
                  <div className="flex justify-between text-[10px] font-mono">
                    <span className="opacity-50">ACTIVE_REACTIONS</span>
                    <span className="text-brand">{messages.reduce((acc: number, m) => acc + (m.reactions ? Object.keys(m.reactions).length : 0), 0)}</span>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}
