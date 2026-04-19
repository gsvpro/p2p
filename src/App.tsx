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
  RefreshCw,
  Key,
  Users,
  Plus
} from 'lucide-react';
import EmojiPicker, { EmojiClickData } from 'emoji-picker-react';
import { iroh } from './lib/iroh';
import { exportIdentity } from './lib/crypto';
import { SecureMessage, Identity, FileTransfer, Group } from './types';
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
  const [searchQuery, setSearchQuery] = useState('');
  const [inputText, setInputText] = useState('');
  const [isEphemeral, setIsEphemeral] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
  const [showEmojiPicker, setShowEmojiPicker] = useState<string | null>(null);
  const [mobilePanel, setMobilePanel] = useState<'peers' | 'chat' | 'metrics'>('chat');
  const [showSettings, setShowSettings] = useState(false);
  const [tempName, setTempName] = useState('');
  const [showAddPeer, setShowAddPeer] = useState(false);
  const [status, setStatus] = useState<{ type: 'info' | 'error', message: string } | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);
  
  const [groups, setGroups] = useState<Group[]>([]);
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [selectedPeers, setSelectedPeers] = useState<string[]>([]);
  const [groupName, setGroupName] = useState('');

  const filteredPeers = peers.filter(id => 
    id.toLowerCase().includes(searchQuery.toLowerCase()) || 
    iroh.getPeerName(id)?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const init = async () => {
      let name = localStorage.getItem('nexus_name');
      if (!name) {
        name = `Node_${Math.floor(Math.random() * 999)}`;
        localStorage.setItem('nexus_name', name);
      }
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

    iroh.onGroupUpdate((newGroups) => {
      setGroups(newGroups);
    });

    iroh.onStatus((type, message) => {
      setStatus({ type, message });
      if (type === 'error') setIsConnecting(false);
      if (message.includes('Tunnel Established')) setIsConnecting(false);

      setTimeout(() => setStatus(null), 5000);
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
      setIsConnecting(true);
      const input = newPeerId.trim();
      
      let targetId = input;
      // If it's not a hex-based iroh ticket (potentially with session suffix), treat as a username for DHT discovery
      const isTicket = /^[a-f0-9]{16}(-[a-f0-9]+)?$/.test(input);
      
      if (!isTicket) {
        setStatus({ type: 'info', message: `DHT Lookup: ${input}` });
        const resolved = await iroh.searchByName(input);
        if (resolved) {
          targetId = resolved;
          setStatus({ type: 'info', message: `Found ${input}: Node_${targetId.slice(0, 4)}` });
        } else {
          setStatus({ type: 'error', message: `Could not find node for: ${input}` });
          setIsConnecting(false);
          return;
        }
      }

      await iroh.connectByTicket(targetId);
      setNewPeerId('');
    }
  };

  const handleBackupIdentity = async () => {
    const qId = iroh.getQuantumIdentity();
    if (qId) {
      const serialized = await exportIdentity(qId);
      const blob = new Blob([serialized], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nexus_identity_${identity?.id.slice(0, 8)}.key`;
      a.click();
    }
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!inputText.trim()) return;

    if (activeGroup) {
      const sentMsg = await iroh.sendGroupMessage(activeGroup, inputText, { ephemeral: isEphemeral });
      if (sentMsg) {
        setMessages(prev => [...prev, sentMsg]);
        setInputText('');
      }
    } else if (activePeer) {
      const sentMsg = await iroh.sendMessage(activePeer, inputText, { ephemeral: isEphemeral });
      if (sentMsg) {
        setMessages(prev => [...prev, sentMsg]);
        setInputText('');
      }
    }
  };

  const handleFileShare = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && activePeer) {
      await iroh.sendFile(activePeer, file);
    }
  };

  const handleCreateGroup = async () => {
    if (groupName.trim() && selectedPeers.length > 0) {
      const newGroup = await iroh.createGroup(groupName, selectedPeers);
      setGroupName('');
      setSelectedPeers([]);
      setShowCreateGroup(false);
      setActiveGroup(newGroup.id);
      setActivePeer(null);
    }
  };
  const handleReaction = async (messageId: string, emoji: string) => {
    if (!activePeer || activeGroup) return; // Currently 1-to-1 only
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
            <span className="font-mono text-xs text-text-secondary truncate max-w-[100px]">{identity?.id}</span>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setMobilePanel(mobilePanel === 'metrics' ? 'chat' : 'metrics')}
              className="md:hidden p-1.5 hover:bg-white/5 rounded transition-colors"
            >
              <RefreshCw className="w-4 h-4 text-brand" />
            </button>
            <button 
              onClick={() => {
                setTempName(identity?.displayName || '');
                setShowSettings(true);
              }}
              className="bg-border hover:bg-gray-700 px-2 xs:px-3 py-1 rounded text-[10px] uppercase font-bold transition-colors"
            >
              Settings
            </button>
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
          <div className="p-4 border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-brand/10 border border-brand/20 flex items-center justify-center">
                <User className="w-4 h-4 text-brand" />
              </div>
              <div className="overflow-hidden">
                <div className="text-[10px] font-bold text-brand uppercase truncate">{identity?.displayName}</div>
                <div className="text-[8px] opacity-30 font-mono truncate cursor-pointer hover:opacity-100" onClick={() => navigator.clipboard.writeText(identity?.id || '')}>
                  {identity?.id}
                </div>
              </div>
            </div>
          </div>

          <div className="p-4 border-b border-border">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[11px] font-bold uppercase tracking-widest opacity-40">Peers</h2>
              <button 
                onClick={() => setShowAddPeer(true)}
                className="text-brand hover:opacity-80 transition-opacity"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
            
            <div className="space-y-1">
              <div className="relative mb-3">
                <input 
                  type="text" 
                  placeholder="Search tickets..."
                  className="w-full bg-bg border border-border rounded py-1.5 pl-3 pr-3 text-[10px] focus:border-brand/40 outline-none"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>

              {filteredPeers.length === 0 && (
                <div className="py-8 text-center px-4">
                  <p className="text-[10px] text-text-secondary uppercase tracking-tight italic">
                    {searchQuery ? 'No matching peers' : 'No active iroh mesh. Connect to a peer ticket.'}
                  </p>
                </div>
              )}

              {filteredPeers.map(peerId => (
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
                    <div className="text-xs font-semibold truncate group-hover:text-brand transition-colors">
                      {iroh.getPeerName(peerId) || `Node_${peerId.slice(0, 4)}`}
                    </div>
                    <div className="text-[10px] opacity-40 truncate font-mono">{peerId}</div>
                  </div>
                  {activePeer === peerId && <div className="w-1.5 h-1.5 bg-brand rounded-full"></div>}
                </div>
              ))}
            </div>

            <div className="mt-8">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-[11px] font-bold uppercase tracking-widest opacity-40">Groups</h2>
                <button 
                  onClick={() => setShowCreateGroup(true)}
                  className="text-brand hover:opacity-80 transition-opacity"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-1">
                {groups.map(group => (
                  <div 
                    key={group.id}
                    onClick={() => {
                      setActiveGroup(group.id);
                      setActivePeer(null);
                    }}
                    className={cn(
                      "flex items-center gap-3 p-2 rounded-md cursor-pointer transition-all group",
                      activeGroup === group.id ? "bg-[#1C1F26] border-l-2 border-brand" : "hover:bg-surface-rail"
                    )}
                  >
                    <div className="w-8 h-8 rounded bg-brand/10 flex items-center justify-center border border-brand/20">
                      <Users className="w-4 h-4 text-brand" />
                    </div>
                    <div className="flex-1 overflow-hidden">
                      <div className="text-xs font-semibold truncate group-hover:text-brand transition-colors">{group.name}</div>
                      <div className="text-[10px] opacity-40 truncate">{group.members.length} Members</div>
                    </div>
                    {activeGroup === group.id && <div className="w-1.5 h-1.5 bg-brand rounded-full"></div>}
                  </div>
                ))}
                {groups.length === 0 && (
                  <p className="text-[9px] opacity-30 italic text-center py-2 uppercase tracking-tighter">No active groups</p>
                )}
              </div>
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
          {!activePeer && !activeGroup ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <Shield className="w-12 h-12 text-border mb-4 opacity-20" />
              <h2 className="text-sm font-bold opacity-30 uppercase tracking-[0.2em]">Iroh Isolated</h2>
              <p className="text-[11px] text-text-secondary mt-2 max-w-xs leading-relaxed uppercase tracking-tighter">
                Enter an Iroh ticket or create a group to establish a document sync tunnel.
              </p>
            </div>
          ) : (
            <>
              <header className="h-14 border-b border-border flex items-center justify-between px-6 bg-bg">
                <div className="flex items-center gap-3">
                  <h1 className="font-bold text-sm">
                    {activeGroup 
                      ? groups.find(g => g.id === activeGroup)?.name 
                      : (activePeer ? (iroh.getPeerName(activePeer) || `Node_${activePeer.slice(0, 4)}`) : '')}
                  </h1>
                  <span className="px-2 py-0.5 rounded bg-surface-rail text-[9px] text-brand border border-brand/20 font-bold uppercase tracking-widest">
                    {activeGroup ? 'PQ_MESH_GROUP' : 'PQXDH_TUNNEL'}
                  </span>
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
                {messages.filter(m => {
                  if (activeGroup) return m.groupId === activeGroup;
                  return !m.groupId && (m.senderId === activePeer || m.receiverId === activePeer);
                }).map((msg) => (
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
                      {msg.senderId === identity?.id ? 'U' : (iroh.getPeerName(msg.senderId)?.[0]?.toUpperCase() || 'P')}
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
                          {msg.senderId === identity?.id ? 'Identity_Local' : (iroh.getPeerName(msg.senderId) || `Node_${msg.senderId.slice(0, 4)}`)}
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
                    disabled={!!activeGroup}
                    className="text-text-secondary hover:text-white mr-2 xs:mr-3 transition-colors group disabled:opacity-20"
                  >
                    <Paperclip className="w-5 h-5 group-hover:text-brand" />
                  </button>
                  <input 
                    type="text" 
                    placeholder={activeGroup ? "Message Group..." : "Message Peer..."} 
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

              {activePeer && iroh.getPeerKeys(activePeer) && (
                <div className="mt-4 pt-4 border-t border-border">
                  <h4 className="text-[9px] uppercase font-bold opacity-30 mb-2 tracking-widest">Active Peer Keys</h4>
                  <div className="space-y-3">
                    <div>
                      <div className="text-[8px] opacity-20 uppercase font-bold mb-1">Peer Classical</div>
                      <div className="font-mono text-[8px] break-all opacity-50 bg-black/20 p-1.5 rounded">
                        {iroh.getPeerKeys(activePeer)?.classical.slice(0, 64)}...
                      </div>
                    </div>
                    <div>
                      <div className="text-[8px] opacity-20 uppercase font-bold mb-1">Peer Quantum</div>
                      <div className="font-mono text-[8px] break-all opacity-50 bg-black/20 p-1.5 rounded">
                        {iroh.getPeerKeys(activePeer)?.pqc.slice(0, 64)}...
                      </div>
                    </div>
                  </div>
                </div>
              )}
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
      
      {/* Add Peer Modal */}
      <AnimatePresence>
        {showAddPeer && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowAddPeer(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="relative w-full max-w-md bg-surface border border-border rounded-xl p-6 shadow-2xl"
            >
              <div className="flex items-center gap-3 mb-6">
                <Plus className="w-5 h-5 text-brand" />
                <h2 className="text-sm font-bold uppercase tracking-widest text-brand">Connect to Node</h2>
              </div>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-[10px] uppercase font-bold opacity-40 mb-2">Node Ticket ID</label>
                  <textarea 
                    value={newPeerId}
                    onChange={(e) => setNewPeerId(e.target.value)}
                    className="w-full bg-bg border border-border rounded px-3 py-2 text-xs font-mono focus:border-brand outline-none transition-colors min-h-[100px] resize-none"
                    placeholder="Paste Peer Ticket..."
                  />
                  <p className="text-[9px] opacity-30 mt-2 italic">Establishing a connection creates a dedicated P2P tunnel with Post-Quantum session keys.</p>
                </div>

                <div className="pt-4 border-t border-border flex justify-end gap-3">
                  <button 
                    onClick={() => setShowAddPeer(false)}
                    className="px-4 py-2 text-[10px] uppercase font-bold opacity-50 hover:opacity-100 transition-opacity"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={() => {
                      handleConnect();
                      setShowAddPeer(false);
                    }}
                    disabled={!newPeerId.trim() || isConnecting}
                    className="bg-brand text-black px-6 py-2 rounded text-[10px] uppercase font-bold hover:opacity-90 disabled:opacity-30 transition-opacity whitespace-nowrap"
                  >
                    {isConnecting ? 'Establishing...' : 'Establish Tunnel'}
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Settings Modal */}
      <AnimatePresence>
        {showSettings && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowSettings(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="relative w-full max-w-md bg-surface border border-border rounded-xl p-6 shadow-2xl"
            >
              <div className="flex items-center gap-3 mb-6">
                <Terminal className="w-5 h-5 text-brand" />
                <h2 className="text-sm font-bold uppercase tracking-widest text-brand">Node Configuration</h2>
              </div>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-[10px] uppercase font-bold opacity-40 mb-2">Display Name</label>
                  <input 
                    type="text" 
                    value={tempName}
                    onChange={(e) => setTempName(e.target.value)}
                    className="w-full bg-bg border border-border rounded px-3 py-2 text-sm font-mono focus:border-brand outline-none transition-colors"
                    placeholder="Enter node alias..."
                  />
                  <p className="text-[9px] opacity-30 mt-2 italic">This name is broadcasted to peers during the HELO handshake.</p>
                </div>

                <div className="p-4 bg-bg rounded border border-border">
                  <h3 className="text-[10px] uppercase font-bold opacity-40 mb-3 tracking-widest flex items-center gap-2">
                    <Key className="w-3 h-3" /> Backup & Recovery
                  </h3>
                  <p className="text-[9px] opacity-50 mb-4 leading-relaxed">
                    Download your cryptographic identity to move this node to another device. Your private keys are never transmitted to any server.
                  </p>
                  <button 
                    onClick={handleBackupIdentity}
                    className="w-full border border-brand/20 hover:bg-brand/5 text-brand text-[10px] uppercase font-bold py-2 rounded flex items-center justify-center gap-2 transition-all"
                  >
                    <Download className="w-3 h-3" /> Export Identity Bundle
                  </button>
                </div>

                <div className="pt-4 border-t border-border flex justify-end gap-3">
                  <button 
                    onClick={() => setShowSettings(false)}
                    className="px-4 py-2 text-[10px] uppercase font-bold opacity-50 hover:opacity-100 transition-opacity"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={() => {
                      iroh.setDisplayName(tempName);
                      setIdentity(iroh.getIdentity());
                      setShowSettings(false);
                    }}
                    className="bg-brand text-black px-6 py-2 rounded text-[10px] uppercase font-bold hover:opacity-90 transition-opacity"
                  >
                    Save Changes
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Status Toasts */}
      <AnimatePresence>
        {status && (
          <motion.div 
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 20, opacity: 0 }}
            className={cn(
              "fixed bottom-6 right-6 z-[200] px-4 py-3 rounded-xl border flex items-center gap-3 shadow-2xl backdrop-blur-md",
              status.type === 'error' ? "bg-red-500/10 border-red-500/20 text-red-500" : "bg-brand/10 border-brand/20 text-brand"
            )}
          >
            {status.type === 'error' ? <Terminal className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
            <span className="text-[11px] font-bold uppercase tracking-wider">{status.message}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Create Group Modal */}
      <AnimatePresence>
        {showCreateGroup && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowCreateGroup(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="relative w-full max-w-md bg-surface border border-border rounded-xl p-6 shadow-2xl"
            >
              <div className="flex items-center gap-3 mb-6">
                <Users className="w-5 h-5 text-brand" />
                <h2 className="text-sm font-bold uppercase tracking-widest text-brand">Establish Mesh Group</h2>
              </div>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-[10px] uppercase font-bold opacity-40 mb-2">Group Name</label>
                  <input 
                    type="text" 
                    value={groupName}
                    onChange={(e) => setGroupName(e.target.value)}
                    className="w-full bg-bg border border-border rounded px-3 py-2 text-sm font-mono focus:border-brand outline-none transition-colors"
                    placeholder="Operation Alpha..."
                  />
                </div>

                <div>
                  <label className="block text-[10px] uppercase font-bold opacity-40 mb-2">Select Members</label>
                  <div className="space-y-2 max-h-40 overflow-y-auto pr-2 terminal-scroll">
                    {peers.map(peerId => (
                      <label key={peerId} className="flex items-center gap-3 p-2 rounded bg-bg border border-border cursor-pointer hover:border-brand/40 transition-colors">
                        <input 
                          type="checkbox" 
                          checked={selectedPeers.includes(peerId)}
                          onChange={(e) => {
                            if (e.target.checked) setSelectedPeers(prev => [...prev, peerId]);
                            else setSelectedPeers(prev => prev.filter(id => id !== peerId));
                          }}
                          className="accent-brand"
                        />
                        <div className="overflow-hidden">
                          <div className="text-xs font-bold truncate">{iroh.getPeerName(peerId) || `Node_${peerId.slice(0, 4)}`}</div>
                          <div className="text-[8px] opacity-30 font-mono truncate">{peerId}</div>
                        </div>
                      </label>
                    ))}
                    {peers.length === 0 && (
                      <p className="text-[10px] opacity-30 italic text-center py-4 uppercase tracking-tighter">Connect to peers first to create a group</p>
                    )}
                  </div>
                </div>

                <div className="pt-4 border-t border-border flex justify-end gap-3">
                  <button 
                    onClick={() => setShowCreateGroup(false)}
                    className="px-4 py-2 text-[10px] uppercase font-bold opacity-50 hover:opacity-100 transition-opacity"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={handleCreateGroup}
                    disabled={!groupName.trim() || selectedPeers.length === 0}
                    className="bg-brand text-black px-6 py-2 rounded text-[10px] uppercase font-bold hover:opacity-90 disabled:opacity-30 transition-opacity"
                  >
                    Instantiate Mesh
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
