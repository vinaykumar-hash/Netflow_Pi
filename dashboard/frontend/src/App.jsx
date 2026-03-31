import React, { useState, useEffect, useRef } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, AreaChart, Area
} from 'recharts';
import {
  Activity, Shield, MessageSquare, AlertTriangle,
  Lock, Unlock, ChevronRight, Send, Search, Terminal,
  Network, Bot, Cpu, MemoryStick, Settings, Power, Loader2, Play, Square, X,
  Database, Zap, ShieldAlert
} from 'lucide-react';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import NetworkGraph from './components/NetworkGraph';

const isAnomalous = (flow) => {
  if (flow.detector === 'autoencoder') {
    return flow.status === 'anomaly' || Number(flow.anomaly_score || 0) > 0;
  }
  if (flow.status) {
    return flow.status === 'anomaly';
  }
  return (flow.flag_anomalies && flow.flag_anomalies.length > 0) ||
    flow.ttl_anomaly ||
    flow.sequence_anomaly ||
    flow.small_packet_anomaly;
};

const defaultAutoencoderStatus = {
  engine: 'heuristic',
  enabled: false,
  training: {
    running: false,
    started_at: null,
    packets_seen: 0,
    packets_trained: 0,
    buffer_size: 1000,
    current_buffer_count: 0,
    batches_completed: 0,
    last_threshold: null,
    last_checkpoint_at: null,
    last_error: null,
    phase: 'idle',
  },
  detection: {
    running: false,
    model_loaded: false,
    model_version: null,
    last_alert_at: null,
    last_error: null,
  },
  model: {
    exists: false,
    version: null,
    trained_at: null,
    threshold: null,
    feature_count: 12,
  },
};


const BentoCard = React.memo(({ children, className = "", bodyClassName = "", title, icon, actions }) => (
  <div className={`bg-[var(--bg-card)] backdrop-blur-xl border-r border-b border-[var(--border-color)] flex flex-col hover:bg-[var(--bg-card-hover)] transition-colors duration-300 group ${className}`}>
    {(title || actions) && (
      <div className="p-4 border-b border-[var(--border-color)] flex justify-between items-center bg-[var(--bg-card-hover)] flex-shrink-0">
        {title && (
          <h3 className="font-bold text-lg flex items-center gap-3 text-[var(--text-primary)] group-hover:text-primary transition-colors tracking-tight">
            {icon} {title}
          </h3>
        )}
        {actions}
      </div>
    )}
    <div className={`flex-grow relative overflow-hidden ${bodyClassName}`}>{children}</div>
  </div>
));

const StatCard = React.memo(({ label, value, icon, color = "text-primary", subtext }) => (
  <div className="bg-[var(--bg-card)] backdrop-blur-md border-l border-[var(--border-color)] p-4 flex items-center gap-4 hover:bg-[var(--bg-card-hover)] transition-colors group h-full">
    <div className={`p-2 bg-[var(--bg-card-hover)] ${color} group-hover:scale-105 transition-transform duration-300`}>
      {icon}
    </div>
    <div className="min-w-0">
      <p className="text-[var(--text-secondary)] text-[10px] uppercase tracking-wider font-semibold truncate">{label}</p>
      <p className="text-xl font-bold font-mono text-[var(--text-primary)] truncate">{value}</p>
      {subtext && <p className="text-[10px] text-[var(--text-secondary)] mt-0.5 truncate">{subtext}</p>}
    </div>
  </div>
));

const ChartContainer = React.memo(({ title, children, className }) => (
  <BentoCard title={title} className={className} bodyClassName="flex flex-col h-full">
    <div className="w-full flex-1 p-4 min-h-0">
      {children}
    </div>
  </BentoCard>
));

const SecurityTable = React.memo(({ flows, formatTime, selectedRows = [], onRowSelect }) => (
  <BentoCard title="RTS Table" icon={<Terminal className="w-5 h-5 text-indigo-400" />} className="flex-1 overflow-hidden h-full">
    <div className="overflow-x-auto h-full scrollbar-thin scrollbar-thumb-[var(--scrollbar-thumb)] scrollbar-track-transparent will-change-transform translate-z-0 overflow-y-auto">
      <table className="w-full text-left border-collapse table-fixed">
        <thead className="text-xs uppercase text-[var(--text-secondary)] bg-[var(--bg-sidebar)] sticky top-0 backdrop-blur-sm z-20 border-b border-[var(--border-color)]">
          <tr>
            <th className="px-6 py-4 font-bold tracking-wider w-[120px]">Time</th>
            <th className="px-6 py-4 font-bold tracking-wider w-1/3">Flow (Source → Dest)</th>
            <th className="px-6 py-4 font-bold tracking-wider w-[100px]">Type</th>
            <th className="px-6 py-4 font-bold tracking-wider w-[100px]">Status</th>
            <th className="px-6 py-4 font-bold tracking-wider w-[80px]">Pkts</th>
            <th className="px-6 py-4 font-bold tracking-wider">Latest Info</th>
          </tr>
        </thead>
        <tbody className="text-sm">
          {flows.map((flow, i) => {
            const isSelected = selectedRows.some(r => r.flow === flow.flow);
            return (
              <tr
                key={flow.flow || i}
                onClick={() => onRowSelect(flow)}
                className={`transition-colors cursor-pointer group h-14 border-b border-[var(--border-color)] last:border-0 ${isSelected ? 'bg-indigo-500/15 border-l border-indigo-500' : 'hover:bg-[var(--bg-card-hover)]'}`}
              >
                <td className="px-6 py-3 font-mono text-xs text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]">
                  {formatTime(flow.last_packet_time)}
                </td>
                <td className="px-6 py-3 font-mono text-[var(--text-accent)] truncate">{flow.flow}</td>
                <td className="px-6 py-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-1 rounded-md text-[10px] uppercase font-bold tracking-wide ${flow.encryption === 'Encrypted' ? 'bg-emerald-500/10 text-[var(--success-text)] border border-emerald-500/20' : 'bg-amber-500/10 text-[var(--warning-text)] border border-amber-500/20'
                      }`}>
                      {flow.encryption}
                    </span>
                    <span className={`px-2 py-1 rounded-md text-[10px] uppercase font-bold tracking-wide border ${flow.detector === 'autoencoder'
                      ? 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20'
                      : 'bg-white/5 text-[var(--text-secondary)] border-[var(--border-color)]'
                      }`}>
                      {flow.detector === 'autoencoder' ? 'AUTOENC' : 'HEUR'}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-3">
                  {isAnomalous(flow) ? (
                    <div className="flex items-center gap-2 text-[var(--danger-text)] bg-rose-500/10 px-2 py-1 rounded-md border border-rose-500/20 w-fit">
                      <AlertTriangle className="w-3 h-3 animate-pulse" />
                      <span className="text-[10px] font-bold">ANOMALY</span>
                    </div>
                  ) : (
                    <Shield className="w-4 h-4 text-[var(--success-text)] opacity-60" />
                  )}
                </td>
                <td className="px-6 py-3 font-mono text-[var(--text-primary)]">{flow.packet_count}</td>
                <td className="px-6 py-3 text-xs text-[var(--text-secondary)] truncate max-w-[200px]">
                  {flow.last_packet_info}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  </BentoCard>
));

const App = () => {
  const apiBaseUrl = `${window.location.protocol}//${window.location.hostname}:8000`;
  const [flows, setFlows] = useState([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    anomalies: 0,
    encryptedRatio: 0
  });
  const [systemStats, setSystemStats] = useState({ cpu: 0, ram: 0 });
  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', text: 'Select any flow or ask any question about the network traffic.' }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef(null);

  const [chartHistory, setChartHistory] = useState(new Array(30).fill({ packet_count: 0 }));
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [portAlerts, setPortAlerts] = useState([]);
  const [viewMode, setViewMode] = useState('list');
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const messageQueue = useRef([]);
  const lastGraphUpdate = useRef(0);

  const [setupStep, setSetupStep] = useState(1);
  const [monitoringMethod, setMonitoringMethod] = useState(1);
  const [devices, setDevices] = useState([]);
  const [selectedTargets, setSelectedTargets] = useState([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const isMonitoringRef = useRef(isMonitoring);
  useEffect(() => {
    isMonitoringRef.current = isMonitoring;
  }, [isMonitoring]);
  const [selectedModel, setSelectedModel] = useState("arcee-ai/trinity-large-preview:free");
  const [showSettings, setShowSettings] = useState(false);
  const [whitelist, setWhitelist] = useState({ ips: [], ports: [], anomaly_threshold: 0, capture_interface: 'any', logging: { all_packets: true, anomalies: true, rag_context: true, graph_edges: true } });
  const [portsText, setPortsText] = useState('');
  const [isLoadingDevices, setIsLoadingDevices] = useState(false);
  const [isSpoofingLoading, setIsSpoofingLoading] = useState(false);
  const [selectedRows, setSelectedRows] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  const [autoencoderStatus, setAutoencoderStatus] = useState(defaultAutoencoderStatus);
  const [autoencoderAction, setAutoencoderAction] = useState('');

  const formatPayloadHex = (payloadHex) => {
    const normalized = String(payloadHex || '').replace(/[:\s]/g, '').trim();
    if (!normalized) return '';
    return normalized.match(/.{1,2}/g)?.join(' ') || normalized;
  };

  useEffect(() => {
    document.documentElement.className = theme === 'light' ? 'light-theme' : '';
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    setSelectedRows((prev) => prev
      .map((selected) => flows.find((flow) => flow.flow === selected.flow) || selected)
      .filter((selected) => flows.some((flow) => flow.flow === selected.flow)));
  }, [flows]);

  const fetchDevices = async () => {
    setIsLoadingDevices(true);
    try {
      const res = await axios.get(`${apiBaseUrl}/api/network/devices/`);
      setDevices(res.data);
    } catch (e) { console.error(e); }
    setIsLoadingDevices(false);
  };

  const fetchInterfaces = async () => {
    try {
      const res = await axios.get(`${apiBaseUrl}/api/network/interfaces/`);
      setInterfaces(Array.isArray(res.data) ? res.data : []);
    } catch (e) { console.error(e); }
  };

  // Fetch interfaces when settings modal opens
  useEffect(() => {
    if (showSettings) fetchInterfaces();
  }, [showSettings]);

  const startSpoofing = async (targets) => {
    setIsSpoofingLoading(true);
    try {
      await axios.post(`${apiBaseUrl}/api/network/spoof/start/`, {
        targets: targets.map(t => t.ip),
        interface: whitelist.capture_interface,
      });
      setIsMonitoring(true);
      setSetupStep(0);
    } catch (e) {
      console.error(e);
      const errorMessage = e?.response?.data?.error || e.message || 'Unknown error';
      window.alert(`Failed to start interception: ${errorMessage}`);
    }
    setIsSpoofingLoading(false);
  };

  const stopSpoofing = async () => {
    try {
      await axios.post(`${apiBaseUrl}/api/network/spoof/stop/`);
      setIsMonitoring(false);
    } catch (e) { console.error(e); }
  };

  const fetchWhitelist = async () => {
    try {
      const res = await axios.get(`${apiBaseUrl}/api/settings/whitelist/`);
      const data = res.data;
      if (!data.logging) data.logging = { all_packets: true, anomalies: true, rag_context: true, graph_edges: true };
      setWhitelist(data);
      setPortsText((data.ports || []).join(', '));
    } catch (e) { console.error(e); }
  };

  const saveWhitelist = async (newWhitelist) => {
    try {
      await axios.post(`${apiBaseUrl}/api/settings/whitelist/`, newWhitelist);
      setWhitelist(newWhitelist);
    } catch (e) { console.error(e); }
  };

  const fetchAutoencoderStatus = async () => {
    try {
      const res = await axios.get(`${apiBaseUrl}/api/autoencoder/status/`);
      setAutoencoderStatus({ ...defaultAutoencoderStatus, ...res.data, training: { ...defaultAutoencoderStatus.training, ...(res.data.training || {}) }, detection: { ...defaultAutoencoderStatus.detection, ...(res.data.detection || {}) }, model: { ...defaultAutoencoderStatus.model, ...(res.data.model || {}) } });
    } catch (e) { console.error(e); }
  };

  const triggerAutoencoderAction = async (path, body = {}) => {
    setAutoencoderAction(path);
    if (path === '/api/autoencoder/train/start/') {
      setAutoencoderStatus((prev) => ({
        ...prev,
        training: {
          ...prev.training,
          running: true,
          phase: 'starting',
          last_error: null,
        },
        detection: {
          ...prev.detection,
          last_error: null,
        },
      }));
    }
    try {
      const res = await axios.post(`${apiBaseUrl}${path}`, body);
      setAutoencoderStatus({ ...defaultAutoencoderStatus, ...res.data, training: { ...defaultAutoencoderStatus.training, ...(res.data.training || {}) }, detection: { ...defaultAutoencoderStatus.detection, ...(res.data.detection || {}) }, model: { ...defaultAutoencoderStatus.model, ...(res.data.model || {}) } });
    } catch (e) {
      console.error(e);
      try {
        const statusRes = await axios.get(`${apiBaseUrl}/api/autoencoder/status/`);
        const nextStatus = {
          ...defaultAutoencoderStatus,
          ...statusRes.data,
          training: { ...defaultAutoencoderStatus.training, ...(statusRes.data.training || {}) },
          detection: { ...defaultAutoencoderStatus.detection, ...(statusRes.data.detection || {}) },
          model: { ...defaultAutoencoderStatus.model, ...(statusRes.data.model || {}) },
        };
        setAutoencoderStatus(nextStatus);
        if (!(path === '/api/autoencoder/train/start/' && nextStatus.training.running)) {
          const errorMessage = e?.response?.data?.error || e.message || 'Unknown error';
          window.alert(`Autoencoder action failed: ${errorMessage}`);
        }
      } catch {
        const errorMessage = e?.response?.data?.error || e.message || 'Unknown error';
        window.alert(`Autoencoder action failed: ${errorMessage}`);
      }
    }
    setAutoencoderAction('');
  };

  useEffect(() => {
    fetchWhitelist();
    fetchAutoencoderStatus();
  }, []);

  useEffect(() => {
    if (!showSettings && !autoencoderStatus.training.running && !autoencoderStatus.detection.running) {
      return undefined;
    }
    fetchAutoencoderStatus();
    const interval = setInterval(fetchAutoencoderStatus, 2000);
    return () => clearInterval(interval);
  }, [showSettings, autoencoderStatus.training.running, autoencoderStatus.detection.running]);

  useEffect(() => {
    // WebSocket Connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.hostname}:8000/ws/packets/`);

    ws.onmessage = (event) => {
      if (!isMonitoringRef.current) return;

      const data = JSON.parse(event.data);
      messageQueue.current.push(data);
    };

    // UI Update Loop (Throttled to 2 seconds)
    const updateInterval = setInterval(() => {
      if (messageQueue.current.length === 0) {
        setChartHistory(prev => [...prev, { packet_count: 0, time: formatTime(Date.now() / 1000) }].slice(-30));
        return;
      }

      const latestBatch = [...messageQueue.current];
      messageQueue.current = [];

      // Process latest data point for chart
      const representativeData = latestBatch[latestBatch.length - 1];
      setChartHistory((prev) => [...prev, {
        packet_count: representativeData.packet_count,
        time: formatTime(representativeData.last_packet_time)
      }].slice(-30));

      const flowUpdates = latestBatch.filter(d => d.type !== 'graph_edge' && d.type !== 'port_alert' && d.type !== 'system_stats');
      const graphUpdates = latestBatch.filter(d => d.type === 'graph_edge');
      const alertUpdates = latestBatch.filter(d => d.type === 'port_alert');
      const sysUpdates = latestBatch.filter(d => d.type === 'system_stats');

      if (sysUpdates.length > 0) {
        const latest = sysUpdates[sysUpdates.length - 1];
        setSystemStats({
          cpu: latest.cpu,
          ram: latest.ram
        });
      }

      // Update Flows
      if (flowUpdates.length > 0) {
        setFlows((prev) => {
          let newFlows = [...prev];
          flowUpdates.forEach(data => {
            const existingIdx = newFlows.findIndex(f => f.flow === data.flow);
            if (existingIdx > -1) {
              newFlows[existingIdx] = data;
            } else {
              newFlows = [data, ...newFlows];
            }
          });
          newFlows.sort((a, b) => parseFloat(b.last_packet_time) - parseFloat(a.last_packet_time));
          newFlows = newFlows.slice(0, 50);

          // Update Stats
          const totalPackets = newFlows.reduce((acc, f) => acc + (f.packet_count || 0), 0);
          const anomalies = newFlows.filter(f => isAnomalous(f)).length;
          const encrypted = newFlows.filter(f => f.encryption === 'Encrypted').length;

          setStats({
            totalPackets,
            anomalies,
            encryptedRatio: (encrypted / newFlows.length) * 100 || 0
          });
          return newFlows;
        });

        // 1.1 Chart History (using the latest flow update as representative)
        const latestFlow = flowUpdates[flowUpdates.length - 1];
        setChartHistory(prev => {
          const newData = {
            packet_count: latestFlow.packet_count || 0,
            time: formatTime(latestFlow.last_packet_time),
            bytes: latestFlow.bytes || 0,
            anomaly: latestFlow.anomaly_score || 0
          };
          return [...prev, newData].slice(-30);
        });

        const alertThreshold = whitelist.anomaly_threshold;
        if (alertThreshold > 0 && latestFlow.anomaly_score >= alertThreshold) {
          const alertKey = `${latestFlow.flow}-${latestFlow.anomaly_score?.toFixed(2)}`;
          setChatMessages(prev => {
            if (prev.some(m => m._key === alertKey)) return prev;
            return [...prev, {
              role: 'assistant',
              _key: alertKey,
              text: `🚨 Anomaly Detected! Score: ${latestFlow.anomaly_score.toFixed(2)} | ${latestFlow.flow || 'Unknown flow'}`,
            }];
          });
        }
      } else {
        setChartHistory(prev => [...prev, { packet_count: 0, time: formatTime(Date.now() / 1000) }].slice(-30));
      }

      if (alertUpdates.length > 0) {
        setPortAlerts(prev => {
          const portMap = new Map(prev.map(p => [p.port, p]));

          alertUpdates.forEach(update => {
            portMap.set(update.port, update);
          });

          const aggregated = Array.from(portMap.values());

          return aggregated.slice(-20);
        });
      }

      // 3. Graph Updates (Throttled to 5s)
      if (graphUpdates.length > 0 && Date.now() - lastGraphUpdate.current > 5000) {
        lastGraphUpdate.current = Date.now();
        console.log(`[GraphDebug] Processing ${graphUpdates.length} graph edges from batch of ${latestBatch.length}`);
        setGraphData(prev => {
          const now = Date.now();

          const currentNodes = prev.nodes || [];
          const currentLinks = prev.links || [];

          const nodes = new Map(currentNodes.map(n => [n.id, n]));
          const links = new Map(currentLinks.map(l => [l.id, l]));

          const isPrivateIP = (nodeId) => {
            if (!nodeId) return false;

            let ip = nodeId;
            if (nodeId.includes('.') && nodeId.includes(':')) {
              ip = nodeId.split(':')[0];
            }
            if (ip === "::1" || ip === "localhost" || ip === "127.0.0.1") return true;
            if (nodeId.startsWith("::1")) return true;

            const parts = ip.split('.');
            if (parts.length !== 4) return false;
            const first = parseInt(parts[0], 10);
            const second = parseInt(parts[1], 10);
            if (first === 10) return true;
            if (first === 172 && second >= 16 && second <= 31) return true;
            if (first === 192 && second === 168) return true;
            return false;
          };

          graphUpdates.forEach(edge => {
            if (!edge.source || !edge.target) return;

            [edge.source, edge.target].forEach(ip => {
              if (!nodes.has(ip)) {
                nodes.set(ip, {
                  id: ip,
                  val: 1,
                  lastSeen: now,
                  color: isPrivateIP(ip) ? "#3b82f6" : "#ef4444"
                });
              } else {
                const n = nodes.get(ip);
                n.lastSeen = now;
                n.val = (n.val || 1) + 0.1;
              }
            });

            const linkId = `${edge.source}-${edge.target}-${edge.dst_port}`;
            const weight = Number(edge.weight) || 1;

            if (links.has(linkId)) {
              const l = links.get(linkId);
              l.value = weight;
              l.lastSeen = now;
            } else {
              links.set(linkId, {
                id: linkId,
                source: edge.source,
                target: edge.target,
                port: edge.dst_port,
                value: weight,
                lastSeen: now
              });
            }
          });

          for (const [id, node] of nodes) {
            if (now - (node.lastSeen || 0) > 60000) nodes.delete(id);
          }
          for (const [id, link] of links) {
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;

            if ((now - (link.lastSeen || 0) > 60000) || !nodes.has(sourceId) || !nodes.has(targetId)) {
              links.delete(id);
            }
          }

          // Calculate Curvature for Multi-Links
          // Group links by source-target pair
          const linksByPair = new Map();
          for (const link of links.values()) {
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;
            const pairId = [sourceId, targetId].sort().join('-');

            if (!linksByPair.has(pairId)) linksByPair.set(pairId, []);
            linksByPair.get(pairId).push(link);
          }

          // Assign curvature
          for (const [pairId, pairLinks] of linksByPair) {
            const count = pairLinks.length;
            if (count > 1) {
              pairLinks.forEach((link, i) => {
                const isSelfLoop = (link.source.id || link.source) === (link.target.id || link.target);
                if (isSelfLoop) {
                  link.curvature = 0.2 + (i * 0.1);
                } else {
                  link.curvature = 0.1 + (i * 0.15);
                }
              });
            } else {
              const isSelfLoop = (pairLinks[0].source.id || pairLinks[0].source) === (pairLinks[0].target.id || pairLinks[0].target);
              pairLinks[0].curvature = isSelfLoop ? 0.2 : 0;
            }
          }

          return {
            nodes: Array.from(nodes.values()),
            links: Array.from(links.values())
          };
        });
      }

    }, 2000);

    return () => {
      ws.close();
      clearInterval(updateInterval);
    };
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages]);

  const formatTime = (epoch) => {
    if (!epoch) return '--:--:--';
    const date = new Date(parseFloat(epoch) * 1000);
    return date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const handleSendMessage = async () => {
    if (!query.trim()) return;

    const userMsg = { role: 'user', text: query };
    setChatMessages(prev => [...prev, userMsg]);
    setQuery('');
    setIsTyping(true);

    try {
      const response = await axios.post(`${apiBaseUrl}/api/chat/`, { messages: query });
      setChatMessages(prev => [...prev, { role: 'assistant', text: response.data.result || response.data }]);
    } catch (error) {
      setChatMessages(prev => [...prev, { role: 'assistant', text: 'Error connecting to analysis engine.' }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleChatSubmit = async (message) => {
    if (!message.trim()) return;

    const userMsg = { role: 'user', text: message };
    setChatMessages(prev => [...prev, userMsg]);
    setInputValue('');
    setIsTyping(true);

    const rowContext = selectedRows.length > 0 ? `
--- CONTEXT: SELECTED FLOWS (${selectedRows.length}) ---
${selectedRows.map(r => `
Flow: ${r.flow}
Description: ${r.last_packet_info}
Packets: ${r.packet_count}
Encryption: ${r.encryption}
Raw Payload Hex: ${formatPayloadHex(r.last_raw_payload_hex) || 'No payload captured'}
`).join('\n---\n')}
    ----------------------------
` : '';

    try {
      const response = await axios.post(`${apiBaseUrl}/api/chat/`, {
        messages: message,
        model: selectedModel,
        selected_row: rowContext
      });
      setChatMessages(prev => [...prev, { role: 'assistant', text: response.data.result || response.data }]);
    } catch (error) {
      setChatMessages(prev => [...prev, { role: 'assistant', text: 'Error connecting to analysis engine.' }]);
    } finally {
      setIsTyping(false);
    }
  };





  return (
    <div className="h-screen flex flex-col bg-[var(--bg-main)] text-[var(--text-primary)] font-inter selection:bg-indigo-500/30 overflow-hidden">

      {/* Modals Overlay */}
      {setupStep > 0 && (
        <div className="fixed inset-0 z-50 bg-[var(--bg-sidebar)]/90 backdrop-blur-xl flex items-center justify-center p-4">
          <div className="bg-[var(--bg-main)] border border-[var(--border-color)] p-8 max-w-2xl w-full">
            {setupStep === 1 && (
              <>
                <h2 className="text-2xl font-bold mb-4 text-[var(--text-primary)]">Setup Monitoring</h2>
                <p className="text-[var(--text-secondary)] mb-8">Choose how you want to capture network traffic.</p>
                <div className="grid grid-cols-2 gap-4">
                  <button onClick={() => { setMonitoringMethod(1); setSetupStep(0); setIsMonitoring(true); }} className="p-6 border border-[var(--border-color)] hover:border-indigo-500 hover:bg-indigo-500/10 transition-colors text-left group">
                    <Activity className="w-8 h-8 text-indigo-400 mb-4 group-hover:scale-110 transition-transform" />
                    <h3 className="text-lg font-bold mb-2">Method 1 (Default)</h3>
                    <p className="text-sm text-[var(--text-secondary)]">Monitor traffic routing directly through this host interface.</p>
                  </button>
                  <button onClick={() => { setMonitoringMethod(2); setSetupStep(2); fetchDevices(); }} className="p-6 border border-[var(--border-color)] hover:border-rose-500 hover:bg-rose-500/10 transition-colors text-left group">
                    <Network className="w-8 h-8 text-rose-400 mb-4 group-hover:scale-110 transition-transform" />
                    <h3 className="text-lg font-bold mb-2">Method 2 (ARP Spoofing)</h3>
                    <p className="text-sm text-[var(--text-secondary)]">Intercept traffic from other devices on the local network.</p>
                  </button>
                </div>
              </>
            )}
            {setupStep === 2 && (
              <>
                <h2 className="text-2xl font-bold mb-4 text-[var(--text-primary)]">Select Devices</h2>
                <p className="text-[var(--text-secondary)] mb-4">Select the target devices to intercept traffic from.</p>
                {isLoadingDevices ? (
                  <div className="flex items-center justify-center p-12 text-indigo-400 gap-3">
                    <Loader2 className="w-6 h-6 animate-spin" /> Fetching ARP table...
                  </div>
                ) : (
                  <div className="max-h-64 overflow-y-auto mb-6 border border-[var(--border-color)]">
                    <table className="w-full text-left text-sm">
                      <thead className="bg-[var(--bg-card-hover)] sticky top-0">
                        <tr>
                          <th className="p-3">Select</th>
                          <th className="p-3">IP Address</th>
                          <th className="p-3">MAC Address</th>
                        </tr>
                      </thead>
                      <tbody className="">
                        {devices.map(d => (
                          <tr key={d.ip} className="hover:bg-[var(--bg-card-hover)] border-b border-[var(--border-color)] last:border-0">
                            <td className="p-3">
                              <input type="checkbox" checked={selectedTargets.some(t => t.ip === d.ip)} onChange={(e) => {
                                if (e.target.checked) setSelectedTargets([...selectedTargets, d]);
                                else setSelectedTargets(selectedTargets.filter(t => t.ip !== d.ip));
                              }} className="accent-rose-500" />
                            </td>
                            <td className="p-3 font-mono text-[var(--text-accent)]">{d.ip}</td>
                            <td className="p-3 font-mono text-[var(--text-secondary)]">{d.mac}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="flex justify-between items-center">
                  <button onClick={() => setSetupStep(1)} className="px-6 py-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors">Back</button>
                  <button disabled={selectedTargets.length === 0 || isSpoofingLoading} onClick={() => startSpoofing(selectedTargets)} className="px-6 py-2 text-sm bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors disabled:opacity-50 flex items-center gap-2">
                    {isSpoofingLoading ? <><Loader2 className="w-4 h-4 animate-spin" /> Executing sysctl & arpspoof...</> : "Start Interception"}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {showSettings && (
        <div className="fixed inset-0 z-50 bg-[var(--bg-sidebar)]/90 backdrop-blur-xl flex items-center justify-center p-4">
          <div className="bg-[var(--bg-main)] border border-[var(--border-color)] p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <h2 className="text-2xl font-bold mb-6 text-[var(--text-primary)] flex items-center gap-3"><Settings className="w-6 h-6 text-indigo-400" /> Settings</h2>

            <div className="space-y-6">
              <div className="bg-[var(--bg-card-hover)] p-4 border border-[var(--border-color)]">
                <h3 className="font-bold mb-4 text-[var(--text-primary)]">Theme</h3>
                <div className="flex gap-4">
                  <button
                    onClick={() => setTheme('dark')}
                    className={`px-4 py-2 text-sm border flex items-center gap-2 transition-colors ${theme === 'dark' ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300' : 'border-[var(--border-color)] hover:bg-white/5 text-[var(--text-secondary)]'}`}
                  >
                    <div className="w-3 h-3 bg-gray-900 border border-white/20"></div> Dark Mode
                  </button>
                  <button
                    onClick={() => setTheme('light')}
                    className={`px-4 py-2 text-sm border flex items-center gap-2 transition-colors ${theme === 'light' ? 'border-rose-500 bg-rose-500/20 text-rose-300' : 'border-[var(--border-color)] hover:bg-white/5 text-[var(--text-secondary)]'}`}
                  >
                    <div className="w-3 h-3 bg-white border border-gray-300"></div> Light Mode
                  </button>
                </div>
              </div>

              <div className="bg-[var(--bg-card-hover)] p-4 border border-[var(--border-color)]">
                <h3 className="font-bold mb-2 text-[var(--text-primary)]">Monitoring Method</h3>
                <div className="flex gap-4 mb-4">
                  <button onClick={() => { stopSpoofing(); setMonitoringMethod(1); setSetupStep(0); setIsMonitoring(true); setShowSettings(false); }} className={`px-4 py-2 text-sm border ${monitoringMethod === 1 ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300' : 'border-[var(--border-color)] hover:bg-[var(--bg-card-hover)]'} transition-colors`}>Method 1 (Local)</button>
                  <button onClick={() => { stopSpoofing(); setMonitoringMethod(2); setSetupStep(2); fetchDevices(); setShowSettings(false); }} className={`px-4 py-2 text-sm border ${monitoringMethod === 2 ? 'border-rose-500 bg-rose-500/20 text-rose-300' : 'border-[var(--border-color)] hover:bg-[var(--bg-card-hover)]'} transition-colors`}>Method 2 (ARP Spoofing)</button>
                </div>
                {monitoringMethod === 2 && (
                  <div className="mt-4">
                    <p className="text-sm font-bold text-[var(--text-secondary)] mb-2">Active Targets:</p>
                    <div className="flex flex-wrap gap-2">
                      {selectedTargets.map(t => <span key={t.ip} className="bg-rose-500/20 text-rose-300 border border-rose-500/30 px-2 py-1 text-xs font-mono">{t.ip}</span>)}
                      {selectedTargets.length === 0 && <span className="text-xs text-[var(--text-secondary)]">No targets selected.</span>}
                    </div>
                  </div>
                )}
              </div>

              {/* Capture Interface Selector */}
              <div className="bg-[var(--bg-card-hover)] p-4 border border-[var(--border-color)]">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-bold text-[var(--text-primary)]">Capture Interface</h3>
                  <button
                    onClick={fetchInterfaces}
                    className="text-[11px] text-indigo-400 hover:text-indigo-300 flex items-center gap-1 border border-indigo-500/30 px-2 py-1 transition-colors hover:bg-indigo-500/10"
                  >
                    <Activity className="w-3 h-3" /> Refresh
                  </button>
                </div>
                <p className="text-xs text-[var(--text-secondary)] mb-3">Select the network interface to capture traffic from. Takes effect on next start.</p>
                {interfaces.length === 0 ? (
                  <p className="text-xs text-[var(--text-secondary)] italic">Loading interfaces…</p>
                ) : (
                  <div className="grid grid-cols-2 gap-2">
                    {interfaces.map(iface => {
                      const selected = (whitelist.capture_interface || 'any') === iface.name;
                      const isUp = iface.up || iface.state === 'UP';
                      return (
                        <button
                          key={iface.name}
                          onClick={() => {
                            const updated = { ...whitelist, capture_interface: iface.name };
                            setWhitelist(updated);
                            saveWhitelist(updated);
                          }}
                          className={`flex items-center justify-between px-3 py-2 border text-left transition-all ${selected
                            ? 'border-indigo-500 bg-indigo-500/15 text-[var(--text-primary)]'
                            : 'border-[var(--border-color)] hover:bg-[var(--bg-card-hover)] text-[var(--text-secondary)]'
                            }`}
                        >
                          <div>
                            <p className="text-sm font-bold font-mono">{iface.name}</p>
                            <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">{iface.type}</p>
                          </div>
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 ${isUp ? 'text-emerald-400 bg-emerald-400/10' : 'text-[var(--text-secondary)] bg-[var(--bg-card-hover)]'
                            }`}>
                            {isUp ? 'UP' : 'DOWN'}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="bg-[var(--bg-card-hover)] p-4 border border-[var(--border-color)]">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-bold text-[var(--text-primary)]">Autoencoder</h3>
                  <button
                    onClick={fetchAutoencoderStatus}
                    className="text-[11px] text-indigo-400 hover:text-indigo-300 flex items-center gap-1 border border-indigo-500/30 px-2 py-1 transition-colors hover:bg-indigo-500/10"
                  >
                    <Activity className="w-3 h-3" /> Refresh
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-3 mb-4 text-xs">
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Engine</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.engine}</p>
                  </div>
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Model</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.model.exists ? `Ready (${autoencoderStatus.model.version || 'unknown'})` : 'Not trained'}</p>
                  </div>
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Training</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.training.phase || 'idle'}</p>
                  </div>
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Threshold</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.model.threshold != null ? Number(autoencoderStatus.model.threshold).toFixed(4) : '--'}</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-3 mb-4">
                  <button
                    onClick={() => triggerAutoencoderAction('/api/autoencoder/train/start/', { replace_existing: true })}
                    disabled={autoencoderStatus.training.running || autoencoderAction !== ''}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {autoencoderAction === '/api/autoencoder/train/start/' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    Start Training
                  </button>
                  <button
                    onClick={() => triggerAutoencoderAction('/api/autoencoder/train/stop/')}
                    disabled={!autoencoderStatus.training.running || autoencoderAction !== ''}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {autoencoderAction === '/api/autoencoder/train/stop/' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
                    Stop Training
                  </button>
                  <button
                    onClick={() => triggerAutoencoderAction('/api/autoencoder/detection/enable/', { enabled: true })}
                    disabled={autoencoderStatus.detection.running || !autoencoderStatus.model.exists || autoencoderAction !== ''}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {autoencoderAction === '/api/autoencoder/detection/enable/' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                    Enable Detection
                  </button>
                  <button
                    onClick={() => triggerAutoencoderAction('/api/autoencoder/detection/disable/')}
                    disabled={!autoencoderStatus.detection.running || autoencoderAction !== ''}
                    className="px-4 py-2 border border-[var(--border-color)] hover:bg-[var(--bg-card-hover)] text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {autoencoderAction === '/api/autoencoder/detection/disable/' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />}
                    Disable Detection
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Packets Seen</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.training.packets_seen}</p>
                  </div>
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Buffer</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.training.current_buffer_count} / {autoencoderStatus.training.buffer_size}</p>
                  </div>
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Packets Trained</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.training.packets_trained}</p>
                  </div>
                  <div className="border border-[var(--border-color)] p-3">
                    <p className="text-[var(--text-secondary)] uppercase tracking-wider mb-1">Batches</p>
                    <p className="font-mono text-[var(--text-primary)]">{autoencoderStatus.training.batches_completed}</p>
                  </div>
                </div>
                {(autoencoderStatus.training.last_error || autoencoderStatus.detection.last_error) && (
                  <p className="mt-3 text-xs text-rose-300 border border-rose-500/30 bg-rose-500/10 p-3 font-mono">
                    {autoencoderStatus.training.last_error || autoencoderStatus.detection.last_error}
                  </p>
                )}
              </div>

              <div className="bg-[var(--bg-card-hover)] p-4 border border-[var(--border-color)]">
                <h3 className="font-bold mb-4 text-[var(--text-primary)]">Whitelist Configuration</h3>
                <label className="block text-sm text-[var(--text-secondary)] mb-1">Whitelisted Ports (comma or space separated)</label>
                <input
                  type="text"
                  value={portsText}
                  onChange={(e) => setPortsText(e.target.value)}
                  onBlur={(e) => {
                    const parsed = e.target.value.split(/[,\s]+/).map(p => parseInt(p.trim())).filter(p => !isNaN(p));
                    setWhitelist(prev => ({ ...prev, ports: parsed }));
                  }}
                  placeholder="e.g. 8000, 8011 443"
                  className="w-full bg-[var(--bg-input)] border border-[var(--border-color)] p-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-indigo-500 mb-4 font-mono"
                />

                <label className="block text-sm text-[var(--text-secondary)] mb-1">Anomaly Score Threshold</label>
                <input type="number" step="0.1" min="0" max="1" value={whitelist.anomaly_threshold} onChange={(e) => setWhitelist({ ...whitelist, anomaly_threshold: parseFloat(e.target.value) || 0 })} className="w-full bg-[var(--bg-input)] border border-[var(--border-color)] p-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-indigo-500 mb-4 font-mono" />

                <button
                  onClick={() => {
                    const parsed = portsText.split(/[,\s]+/).map(p => parseInt(p.trim())).filter(p => !isNaN(p));
                    const updated = { ...whitelist, ports: parsed };
                    setWhitelist(updated);
                    saveWhitelist(updated);
                  }}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-bold transition-colors"
                >Save Whitelist</button>
              </div>

              {/* Logging Toggles */}
              <div className="bg-[var(--bg-card-hover)] p-4 border border-[var(--border-color)]">
                <h3 className="font-bold mb-1 text-[var(--text-primary)]">Log Files</h3>
                <p className="text-xs text-[var(--text-secondary)] mb-4">Disable logs to reduce disk I/O. Changes take effect within ~1 second.</p>
                <div className="space-y-3">
                  {[
                    { key: 'all_packets', label: 'All Packets', path: 'logs/all_packets.csv', desc: 'Every raw captured packet' },
                    { key: 'anomalies', label: 'Anomaly Events', path: 'docs/anomalies.csv', desc: 'Flows that exceed the anomaly threshold' },
                    { key: 'rag_context', label: 'RAG Context', path: 'docs/rag_context.csv', desc: 'Context fed to the AI assistant' },
                    { key: 'graph_edges', label: 'Graph Edges', path: 'logs/debug_graph_edges.csv', desc: 'Network topology edges' },
                  ].map(({ key, label, path, desc }) => {
                    const enabled = whitelist.logging?.[key] ?? true;
                    return (
                      <div key={key} className="flex items-center justify-between gap-4 py-2 border-b border-white/[0.06] last:border-0">
                        <div>
                          <p className="text-sm font-semibold text-[var(--text-primary)]">{label}</p>
                          <p className="text-[11px] text-[var(--text-secondary)] font-mono">{path}</p>
                          <p className="text-[11px] text-[var(--text-secondary)]">{desc}</p>
                        </div>
                        <button
                          onClick={() => {
                            const updated = {
                              ...whitelist,
                              logging: { ...(whitelist.logging || {}), [key]: !enabled }
                            };
                            setWhitelist(updated);
                            saveWhitelist(updated);
                          }}
                          className={`relative flex-shrink-0 w-11 h-6 rounded-full transition-colors ${enabled ? 'bg-indigo-500' : 'bg-[var(--bg-card-hover)]'
                            }`}
                        >
                          <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${enabled ? 'translate-x-5' : 'translate-x-0'
                            }`} />
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="mt-8 flex justify-end">
              <button onClick={() => setShowSettings(false)} className="px-6 py-2 border border-[var(--border-color)] hover:bg-[var(--bg-card-hover)] text-sm transition-colors text-[var(--text-primary)]">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Background Gradients*/}
      <div className="fixed inset-0 pointer-events-none opacity-20 z-0">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-500/10 blur-[120px]" />
        <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-500/10 blur-[120px]" />
      </div>

      {/* Header*/}
      <header className="flex justify-between items-center border-b border-[var(--border-color)] bg-[var(--bg-header)] relative z-20 h-16">
        <div className="flex items-center h-full px-6 border-r border-[var(--border-color)] bg-[var(--bg-card-hover)]">

          <div>
            <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
              NETFLOW
            </h1>
          </div>
        </div>

        <div className="flex items-center h-full flex-grow justify-end">
          {/* View Toggles */}
          <div className="flex h-full border-l border-[var(--border-color)]">
            <button
              onClick={() => setViewMode('list')}
              className={`px-6 h-full text-xs font-bold transition-colors flex items-center gap-2 border-r border-[var(--border-color)] ${viewMode === 'list' ? 'bg-indigo-600 text-white' : 'text-[var(--text-secondary)] hover:bg-white/5'}`}
            >
              <Terminal className="w-4 h-4" /> LIST
            </button>
            <button
              onClick={() => setViewMode('graph')}
              className={`px-6 h-full text-xs font-bold transition-colors flex items-center gap-2 ${viewMode === 'graph' ? 'bg-indigo-600 text-white' : 'text-[var(--text-secondary)] hover:bg-white/5'}`}
            >
              <Network className="w-4 h-4" /> GRAPH
            </button>
          </div>

          {/* Stats Row */}
          <div className="flex h-full border-[var(--border-color)] justify-center items-center gap-6 bg-[var(--bg-header)]">
            <div className="flex flex-col h-full">
              {/* <span className="text-[10px] text-secondary uppercase font-bold tracking-widest mb-1 opacity-50">System Metrics</span> */}
              <div className="flex h-full overflow-hidden border-r border-[var(--border-color)] bg-black/5 fustat tracking-tight" >
                <StatCard
                  label="CPU"
                  value={`${systemStats.cpu}%`}
                  icon={<Activity className="w-3.5 h-3.5" />}
                  color="text-[var(--text-accent)]"
                />
                <StatCard
                  label="RAM"
                  value={`${systemStats.ram}%`}
                  icon={<Database className="w-3.5 h-3.5" />}
                  color="text-[var(--text-accent)]"
                />
                <StatCard
                  label="Live Flows"
                  value={flows.length}
                  icon={<Zap className="w-3.5 h-3.5" />}
                  color="text-[var(--text-accent)]"
                />
                <StatCard
                  label="Anomalies"
                  value={stats.anomalies}
                  icon={<ShieldAlert className="w-3.5 h-3.5" />}
                  color={stats.anomalies > 0 ? "text-[var(--danger-text)]" : "text-[var(--text-secondary)]"}
                />
                <StatCard
                  label="Secured"
                  value={`${stats.encryptedRatio.toFixed(1)}%`}
                  icon={<Lock className="w-3.5 h-3.5" />}
                  color="text-[var(--success-text)]"
                />
              </div>
            </div>
            <div className="flex items-center gap-2 px-4 border-l border-[var(--border-color)]">
              <button
                onClick={() => {
                  if (monitoringMethod === 2) {
                    if (isMonitoring) stopSpoofing();
                    else startSpoofing(selectedTargets);
                  } else {
                    setIsMonitoring(!isMonitoring);
                  }
                }}
                className={`p-2 border transition-colors ${isMonitoring ? 'bg-rose-500/20 border-rose-500/50 text-rose-400 hover:bg-rose-500/30' : 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/30'}`}
                title={isMonitoring ? "Stop Monitoring" : "Start Monitoring"}
              >
                {isMonitoring ? <Square className="w-4 h-4" fill="currentColor" /> : <Play className="w-4 h-4" fill="currentColor" />}
              </button>
              <button onClick={() => setShowSettings(true)} className="p-2 border border-[var(--border-color)] hover:bg-white/5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors">
                <Settings className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Grid*/}
      <main className="grid grid-cols-12 flex-grow relative z-10 border-b border-[var(--border-color)] overflow-hidden min-h-0">

        {/* Left Column*/}
        <div className="col-span-8 flex flex-col border-r border-[var(--border-color)] overflow-hidden h-full">

          {/* Top Row*/}
          <div className="grid grid-cols-2 h-72 border-b border-[var(--border-color)] flex-shrink-0">
            <ChartContainer title="Traffic Volume" className="border-r border-[var(--border-color)]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartHistory}>
                  <defs>
                    <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Tooltip
                    contentStyle={{ backgroundColor: 'var(--bg-main)', borderColor: 'var(--border-color)', borderRadius: '0px' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                    labelStyle={{ color: 'var(--text-secondary)' }}
                  />
                  <XAxis dataKey="time" hide />
                  <YAxis hide />
                  <Area
                    type="monotone"
                    dataKey="packet_count"
                    stroke="#6366f1"
                    strokeWidth={1.5}
                    fillOpacity={1}
                    fill="url(#colorPackets)"
                    isAnimationActive={true}
                    connectNulls={true}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </ChartContainer>

            <ChartContainer title="Port Activity" className="border-none">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={portAlerts}>
                  <defs>
                    <linearGradient id="colorPorts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.3} />
                    </linearGradient>
                  </defs>
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                    contentStyle={{ backgroundColor: 'var(--bg-main)', borderColor: 'var(--border-color)', borderRadius: '0px' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                    labelStyle={{ color: 'var(--text-secondary)' }}
                  />
                  <Bar
                    dataKey="packets"
                    fill="url(#colorPorts)"
                    radius={[2, 2, 0, 0]}
                    barSize={12}
                    isAnimationActive={true}
                  />
                  <XAxis dataKey="port" hide />
                </BarChart>
              </ResponsiveContainer>
            </ChartContainer>
          </div>

          {/* Bottom Row*/}
          <div className="flex-1 min-h-0 relative bg-[var(--bg-input)]">
            {viewMode === 'list' && (
              <SecurityTable
                flows={flows}
                formatTime={formatTime}
                selectedRows={selectedRows}
                onRowSelect={(flow) => {
                  setSelectedRows(prev => {
                    const exists = prev.some(r => r.flow === flow.flow);
                    if (exists) return prev.filter(r => r.flow !== flow.flow);
                    return [...prev, flow];
                  });
                }}
              />
            )}

            {viewMode === 'graph' && (
              <BentoCard
                title="Live Network Topology"
                icon={<Network className="w-5 h-5 text-indigo-400" />}
                className="h-full border-none"
                bodyClassName="h-full"
                actions={
                  <div className="text-xs text-[var(--text-secondary)] flex gap-4 font-mono">
                    <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-none bg-blue-500"></span> Internal</span>
                    <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-none bg-rose-500"></span> External</span>
                  </div>
                }
              >
                <NetworkGraph nodes={graphData.nodes} links={graphData.links} theme={theme} />
              </BentoCard>
            )}
          </div>
        </div>

        {/* Right Column*/}
        <div className="col-span-4 h-[calc(100vh-64px)] bg-[var(--bg-sidebar)] overflow-hidden sticky top-16 flex flex-col">
          <BentoCard
            title="Flow AI"
            icon={<Bot className="w-5 h-5 text-emerald-400" />}
            className="flex-1 overflow-hidden border-none"
            bodyClassName="flex flex-col"
            actions={
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="bg-[var(--bg-input)] border border-[var(--border-color)] text-xs text-[var(--text-secondary)] focus:outline-none focus:border-indigo-500 py-1 px-2 font-mono scrollbar-thin rounded-none"
              >
                <option value="arcee-ai/trinity-large-preview:free">Trinity Large (Free)</option>
                <option value="google/gemini-2.5-flash:free">Gemini 2.5 Flash</option>
                <option value="meta-llama/llama-3.3-70b-instruct:free">Llama 3.3 70B</option>
                <option value="deepseek/deepseek-r1:free">DeepSeek R1</option>
                <option value="qwen/qwen-2.5-coder-32b-instruct:free">Qwen 2.5 Coder 32B</option>
              </select>
            }
          >
            <div className="flex flex-col h-full bg-[var(--bg-sidebar)]/20 overflow-hidden">
              <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-[var(--scrollbar-thumb)] scrollbar-track-transparent min-h-0">
                {chatMessages.map((msg, i) => (
                  <div
                    key={i}
                    className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[85%] p-3 text-sm border ${msg.role === 'user'
                        ? 'bg-indigo-600 text-white border-indigo-500'
                        : 'bg-[var(--bg-card-hover)] text-[var(--text-primary)] border-[var(--border-color)]'
                        }`}
                    >
                      {msg.role === 'assistant' && (
                        <div className="flex items-center gap-2 mb-2 text-indigo-300 text-xs font-bold uppercase tracking-wider">
                          <Bot className="w-3 h-3" /> NetFlow AI
                        </div>
                      )}
                      <ReactMarkdown
                        components={{
                          code: ({ node, inline, className, children, ...props }) => (
                            <code className={`${className} bg-[var(--bg-input)] px-1 py-0.5 font-mono text-xs border border-[var(--border-color)]`} {...props}>{children}</code>
                          )
                        }}
                      >{msg.text}</ReactMarkdown>
                    </div>
                  </div>
                ))}
                {isTyping && (
                  <div className="flex justify-start animate-pulse">
                    <div className="bg-[var(--bg-card-hover)] p-4 w-12 h-10 flex items-center justify-center gap-1 border border-[var(--border-color)]">
                      <span className="w-1 h-1 bg-[var(--accent-primary)] rounded-none animate-bounce" style={{ animationDelay: '0ms' }} />
                      <span className="w-1 h-1 bg-[var(--accent-primary)] rounded-none animate-bounce" style={{ animationDelay: '150ms' }} />
                      <span className="w-1 h-1 bg-[var(--accent-primary)] rounded-none animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>

              {/* Context Preview & Chat Input */}
              <div className="border-t border-[var(--border-color)] bg-[var(--bg-input)] backdrop-blur-xl">
                {selectedRows.length > 0 && (
                  <div className="border-b border-[var(--border-color)] p-3 max-h-56 overflow-y-auto scrollbar-thin">
                    <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-3">Selected Flow Payload</div>
                    <div className="space-y-3">
                      {selectedRows.map((row) => (
                        <div key={`${row.flow}-payload`} className="border border-[var(--border-color)] bg-[var(--bg-card-hover)] p-3">
                          <div className="text-[10px] font-mono text-[var(--text-accent)] mb-2 break-all">{row.flow}</div>
                          <div className="text-[10px] text-[var(--text-secondary)] mb-2">{row.last_packet_info}</div>
                          <pre className="text-[10px] leading-5 font-mono text-[var(--text-primary)] whitespace-pre-wrap break-all max-h-28 overflow-y-auto scrollbar-thin">
                            {formatPayloadHex(row.last_raw_payload_hex) || 'No raw payload captured for the latest packet in this flow.'}
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {/* Selected Context Chips */}
                {selectedRows.length > 0 && (
                  <div className="p-2 flex flex-wrap gap-2 border-b border-[var(--border-color)] max-h-32 overflow-y-auto scrollbar-thin">
                    {selectedRows.map(row => (
                      <div key={row.flow} className="flex items-center gap-2 bg-indigo-500/10 border border-indigo-500/30 px-2 py-1 text-[10px] font-mono text-[var(--text-accent)] group">
                        <span className="truncate max-w-[150px]">{row.flow}</span>
                        <button
                          onClick={() => setSelectedRows(prev => prev.filter(r => r.flow !== row.flow))}
                          className="hover:text-rose-400 transition-colors"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (!inputValue.trim()) return;
                    handleChatSubmit(inputValue);
                    setInputValue('');
                  }}
                  className="relative flex"
                >
                  <input
                    type="text"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder={selectedRows.length > 0 ? `Ask about ${selectedRows.length} selected flows...` : "Ask about network anomalies..."}
                    className="w-full bg-transparent py-4 pl-4 pr-12 text-sm text-[var(--text-primary)] focus:outline-none focus:bg-white/5 placeholder:text-[var(--text-secondary)] transition-colors rounded-none"
                  />
                  <button
                    type="submit"
                    className="absolute right-0 top-0 h-full px-4 text-indigo-400 hover:text-indigo-300 hover:bg-white/5 transition-colors border-l border-[var(--border-color)] rounded-none"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </form>
              </div>
            </div>
          </BentoCard>
        </div>
      </main>
    </div>
  );
};

export default App;
