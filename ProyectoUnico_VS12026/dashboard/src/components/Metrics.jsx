import { useState, useEffect } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import { HardDrive, Server, Activity, Layers, MemoryStick, Power, PowerOff, XCircle } from 'lucide-react';
import axios from 'axios';
import ProcessModal from './ProcessModal';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const Metrics = ({ metrics, role }) => {
  const [history, setHistory] = useState([]);
  const [topProcesses, setTopProcesses] = useState([]);
  const [metricsEnabled, setMetricsEnabled] = useState(true);
  
  // Estados para el Modal y Notificaciones
  const [selectedPid, setSelectedPid] = useState(null);
  const [modalInfo, setModalInfo] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [modalError, setModalError] = useState(null);
  const [message, setMessage] = useState(null);

  // Obtener estado inicial del toggle
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/status`);
        setMetricsEnabled(res.data.metrics_enabled);
      } catch (err) { /* silenciar */ }
    };
    fetchStatus();
  }, []);

  // Actualizar historial con las métricas nuevas
  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/metrics`);
        const m = res.data;
        if (m && !m.error) {
          setHistory(prev => {
            const newHistory = [...prev, {
              time: new Date().toLocaleTimeString(),
              usada: m.memoria_usada / (1024 * 1024),
              libre: m.memoria_libre / (1024 * 1024),
              cache: (m.memoria_cache || 0) / (1024 * 1024),
              swap: (m.swap_usada || 0) / (1024 * 1024),
              activas: (m.paginas_activas || 0) / (1024 * 1024),
              inactivas: (m.paginas_inactivas || 0) / (1024 * 1024),
              fallosMenores: m.fallos_menores || 0,
              fallosMayores: m.fallos_mayores || 0,
            }];
            if (newHistory.length > 20) newHistory.shift();
            return newHistory;
          });
          setMessage(null);
        }
      } catch (err) {
        setMessage({ type: 'error', text: 'Métricas no disponibles o servicio apagado.' });
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 1000);
    return () => clearInterval(interval);
  }, []);

  // Obtener top 20 procesos
  useEffect(() => {
    const fetchTop = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/top_processes`);
        if (Array.isArray(res.data)) {
          setTopProcesses(res.data.slice(0, 20));
        }
      } catch (err) {
        setTopProcesses([]);
      }
    };
    fetchTop();
    const interval = setInterval(fetchTop, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleMetrics = async () => {
    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/toggle_metrics`);
      setMetricsEnabled(res.data.metrics_enabled);
    } catch (err) { console.error(err); }
  };

  // Matar proceso CON confirmación
  const handleKill = async (e, pid, name) => {
    e.stopPropagation(); // Evitar que se abra el modal al hacer clic en el botón
    const confirmed = window.confirm(
      `⚠️ ¿Estás seguro de que deseas terminar el proceso?\n\nPID: ${pid}\nNombre: ${name}\n\nEsta acción no se puede deshacer y podría afectar la estabilidad del sistema.`
    );
    if (!confirmed) return;

    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/kill?pid=${pid}`);
      if (res.data.status === 'success') {
        setMessage({ type: 'success', text: `Proceso ${name} (PID: ${pid}) terminado exitosamente.` });
      } else {
        setMessage({ type: 'error', text: res.data.message || 'Error al matar proceso.' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Error de red o servidor.' });
    }
    setTimeout(() => setMessage(null), 4000);
  };

  // Abrir modal con info de proceso
  const handleRowClick = async (pid) => {
    setSelectedPid(pid);
    setModalLoading(true);
    setModalError(null);
    setModalInfo(null);
    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/process_info?pid=${pid}`);
      setModalInfo(res.data);
    } catch (err) {
      setModalError(err.response?.status === 404 ? 'Proceso no encontrado o ya terminó.' : 'Error de red.');
    } finally {
      setModalLoading(false);
    }
  };

  if (!metrics) {
    return <div className="flex justify-center items-center h-64 text-gray-500">Cargando métricas...</div>;
  }

  const formatMB = (bytes) => (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  const totalMemoryMB = (metrics.memoria_usada + metrics.memoria_libre) / (1024 * 1024);

  // --- GRÁFICA 1: Uso de Memoria y Swap en el tiempo ---
  const memSwapData = {
    labels: history.map(h => h.time),
    datasets: [
      {
        label: 'Memoria Usada (MB)',
        data: history.map(h => h.usada),
        borderColor: 'rgba(59, 130, 246, 1)',
        backgroundColor: 'rgba(59, 130, 246, 0.15)',
        fill: true, tension: 0.4,
      },
      {
        label: 'Swap Usada (MB)',
        data: history.map(h => h.swap),
        borderColor: 'rgba(249, 115, 22, 1)',
        backgroundColor: 'rgba(249, 115, 22, 0.15)',
        fill: true, tension: 0.4,
      }
    ],
  };

  // --- GRÁFICA 2: Memoria Libre vs Caché vs Usada ---
  const memDistData = {
    labels: ['Usada', 'Libre', 'Caché'],
    datasets: [{
      data: [
        metrics.memoria_usada / (1024 * 1024),
        metrics.memoria_libre / (1024 * 1024),
        (metrics.memoria_cache || 0) / (1024 * 1024),
      ],
      backgroundColor: ['rgba(59, 130, 246, 0.8)', 'rgba(16, 185, 129, 0.8)', 'rgba(168, 85, 247, 0.8)'],
      borderColor: ['rgba(59, 130, 246, 1)', 'rgba(16, 185, 129, 1)', 'rgba(168, 85, 247, 1)'],
      borderWidth: 2,
    }],
  };

  // --- GRÁFICA 3: Páginas Activas vs Inactivas ---
  const pagesData = {
    labels: history.map(h => h.time),
    datasets: [
      {
        label: 'Páginas Activas (MB)',
        data: history.map(h => h.activas),
        borderColor: 'rgba(34, 197, 94, 1)',
        backgroundColor: 'rgba(34, 197, 94, 0.15)',
        fill: true, tension: 0.4,
      },
      {
        label: 'Páginas Inactivas (MB)',
        data: history.map(h => h.inactivas),
        borderColor: 'rgba(239, 68, 68, 1)',
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
        fill: true, tension: 0.4,
      }
    ],
  };

  // --- GRÁFICA 4: Fallos de Página Menores vs Mayores ---
  const faultsData = {
    labels: history.map(h => h.time),
    datasets: [
      {
        label: 'Fallos Menores',
        data: history.map(h => h.fallosMenores),
        borderColor: 'rgba(251, 191, 36, 1)',
        backgroundColor: 'rgba(251, 191, 36, 0.15)',
        fill: true, tension: 0.4,
      },
      {
        label: 'Fallos Mayores',
        data: history.map(h => h.fallosMayores),
        borderColor: 'rgba(239, 68, 68, 1)',
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
        fill: true, tension: 0.4,
      }
    ],
  };

  const lineOptions = (maxY) => ({
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    scales: {
      y: {
        min: 0,
        ...(maxY ? { max: maxY } : {}),
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#9ca3af' }
      },
      x: { grid: { display: false }, ticks: { color: '#9ca3af', maxTicksLimit: 10 } }
    },
    plugins: { legend: { labels: { color: '#fff', boxWidth: 12 } } }
  });

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'bottom', labels: { color: '#fff', padding: 16 } }
    },
    cutout: '65%',
  };

  const getMemoryDisplay = (pages) => {
    if (pages == null) return '0.00 MB';
    const totalRam = metrics.memoria_usada + metrics.memoria_libre;
    const bytes = pages * 4096;
    const mb = (bytes / (1024 * 1024)).toFixed(2);
    const percent = totalRam > 0 ? ((bytes / totalRam) * 100).toFixed(2) : '0.00';
    return `${mb} MB (${percent}%)`;
  };

  return (
    <div className="space-y-6">
      {message && (
        <div className={`p-4 rounded-lg border ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400' : 'bg-red-500/10 border-red-500/50 text-red-400'}`}>
          {message.text}
        </div>
      )}

      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Métricas de Sistema (Syscalls)</h2>
        {role === 'admin_user' && (
          <button
            onClick={handleToggleMetrics}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              metricsEnabled
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'
                : 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
            }`}
          >
            {metricsEnabled ? <Power size={16} /> : <PowerOff size={16} />}
            {metricsEnabled ? 'Métricas Activas' : 'Métricas Desactivadas'}
          </button>
        )}
      </div>
      
      {/* Tarjetas de resumen */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl shadow-lg">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2.5 bg-blue-500/20 text-blue-500 rounded-xl"><Server size={20} /></div>
            <h3 className="text-gray-400 text-sm font-medium">Memoria Usada</h3>
          </div>
          <p className="text-2xl font-bold text-white">{formatMB(metrics.memoria_usada)}</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl shadow-lg">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2.5 bg-emerald-500/20 text-emerald-500 rounded-xl"><HardDrive size={20} /></div>
            <h3 className="text-gray-400 text-sm font-medium">Memoria Libre</h3>
          </div>
          <p className="text-2xl font-bold text-white">{formatMB(metrics.memoria_libre)}</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl shadow-lg">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2.5 bg-purple-500/20 text-purple-500 rounded-xl"><MemoryStick size={20} /></div>
            <h3 className="text-gray-400 text-sm font-medium">Caché / Swap</h3>
          </div>
          <p className="text-lg font-bold text-white">
            <span className="text-xs text-gray-500 mr-1">Caché:</span>{formatMB(metrics.memoria_cache || 0)}
            <br/>
            <span className="text-xs text-gray-500 mr-1">Swap:</span>{formatMB(metrics.swap_usada || 0)}
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl shadow-lg">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2.5 bg-amber-500/20 text-amber-500 rounded-xl"><Activity size={20} /></div>
            <h3 className="text-gray-400 text-sm font-medium">Fallos de Página</h3>
          </div>
          <p className="text-lg font-bold text-white">
            <span className="text-xs text-gray-500 mr-1">Menores:</span>{metrics.fallos_menores?.toLocaleString()}
            <br/>
            <span className="text-xs text-gray-500 mr-1">Mayores:</span>{metrics.fallos_mayores?.toLocaleString()}
          </p>
        </div>
      </div>

      {/* Fila de 2 gráficas */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg">
          <h3 className="text-lg font-medium text-white mb-4">Uso de Memoria y Swap en el Tiempo</h3>
          <div className="h-64">
            <Line data={memSwapData} options={lineOptions(totalMemoryMB)} />
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg">
          <h3 className="text-lg font-medium text-white mb-4">Memoría Libre vs. Memoría Caché vs. Memoría Utilizada</h3>
          <div className="h-64 flex items-center justify-center">
            <Doughnut data={memDistData} options={doughnutOptions} />
          </div>
        </div>
      </div>

      {/* Fila de 2 gráficas */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg">
          <h3 className="text-lg font-medium text-white mb-4">Páginas Activas vs. Páginas Inactivas</h3>
          <div className="h-64">
            <Line data={pagesData} options={lineOptions(null)} />
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg">
          <h3 className="text-lg font-medium text-white mb-4">Fallo de páginas Menores vs. Fallo de páginas Mayores</h3>
          <div className="h-64">
            <Line data={faultsData} options={lineOptions(null)} />
          </div>
        </div>
      </div>

      {/* Tabla Top 20 procesos */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl shadow-lg overflow-hidden">
        <div className="p-6 border-b border-gray-800">
          <h3 className="text-lg font-medium text-white flex items-center gap-2">
            <Layers size={20} className="text-blue-400" />
            Top 20 Procesos por Consumo de Memoria
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-800/50 border-b border-gray-800">
                <th className="p-4 text-sm font-semibold text-gray-400 w-12">#</th>
                <th className="p-4 text-sm font-semibold text-gray-400">PID</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Nombre</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Uso de Memoria</th>
                {role === 'admin_user' && <th className="p-4 text-sm font-semibold text-gray-400 text-right">Acciones</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {topProcesses.map((proc, idx) => (
                <tr 
                  key={idx} 
                  onClick={() => handleRowClick(proc.pid)}
                  className="hover:bg-gray-800/50 transition-colors cursor-pointer group"
                >
                  <td className="p-4 text-gray-500 font-mono text-sm">{idx + 1}</td>
                  <td className="p-4 text-gray-300 font-mono">{proc.pid}</td>
                  <td className="p-4 text-white font-medium group-hover:text-blue-400 transition-colors">{proc.name}</td>
                  <td className="p-4 text-gray-400">{getMemoryDisplay(proc.memory_usage)}</td>
                  {role === 'admin_user' && (
                    <td className="p-4 text-right">
                      <button
                        onClick={(e) => handleKill(e, proc.pid, proc.name)}
                        className="p-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors flex items-center justify-center ml-auto gap-2 text-sm opacity-0 group-hover:opacity-100"
                        title="Matar proceso"
                      >
                        <XCircle size={16} /> Matar
                      </button>
                    </td>
                  )}
                </tr>
              ))}
              {topProcesses.length === 0 && (
                <tr>
                  <td colSpan="4" className="p-8 text-center text-gray-500">Cargando procesos...</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de información del proceso */}
      <ProcessModal 
        pid={selectedPid} 
        processInfo={modalInfo} 
        error={modalError} 
        isLoading={modalLoading} 
        onClose={() => setSelectedPid(null)} 
      />
    </div>
  );
};

export default Metrics;
