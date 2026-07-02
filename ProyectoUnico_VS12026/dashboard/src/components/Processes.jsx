import { useState, useEffect } from 'react';
import axios from 'axios';
import { Cpu, XCircle, Search, ChevronLeft, ChevronRight, Info, Power, PowerOff } from 'lucide-react';
import ProcessModal from './ProcessModal';

const Processes = ({ role, totalRam = 0 }) => {
  const [processes, setProcesses] = useState([]);
  const [message, setMessage] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [pidLookup, setPidLookup] = useState("");
  const [processInfo, setProcessInfo] = useState(null);
  const [scanEnabled, setScanEnabled] = useState(true);

  // Estados para el modal
  const [selectedPid, setSelectedPid] = useState(null);
  const [modalInfo, setModalInfo] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [modalError, setModalError] = useState(null);

  // Estado inicial del toggle
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/status`);
        setScanEnabled(res.data.scan_enabled);
      } catch (err) { /* silenciar */ }
    };
    fetchStatus();
  }, []);

  // Debounce para búsqueda
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 500);
    return () => clearTimeout(timer);
  }, [search]);

  // Obtener procesos paginados
  useEffect(() => {
    const fetchProcesses = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/processes?page=${page}&search=${debouncedSearch}`);
        if (res.data && res.data.data) {
          setProcesses(res.data.data);
          setTotalPages(res.data.total_pages || 1);
        }
      } catch (err) {
        console.error("Error fetching processes:", err);
      }
    };

    fetchProcesses();
    const interval = setInterval(fetchProcesses, 1000);
    return () => clearInterval(interval);
  }, [page, debouncedSearch]);

  // Matar proceso CON confirmación
  const handleKill = async (e, pid, name) => {
    e.stopPropagation(); // Evitar que se abra el modal
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

  // Buscar proceso por PID (syscall 464)
  const handleLookupPid = async (e) => {
    e.preventDefault();
    if (!pidLookup.trim()) return;

    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/process_info?pid=${pidLookup}`);
      setProcessInfo(res.data);
    } catch (err) {
      if (err.response && err.response.status === 404) {
        setProcessInfo(null);
        setMessage({ type: 'error', text: `Proceso con PID ${pidLookup} no encontrado.` });
        setTimeout(() => setMessage(null), 3000);
      }
    }
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

  // Toggle escaneo de procesos
  const handleToggleScan = async () => {
    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/toggle_scan`);
      setScanEnabled(res.data.scan_enabled);
    } catch (err) { console.error(err); }
  };

  const getMemoryDisplay = (pages) => {
    if (pages == null) return '0.00 MB (0.00%)';
    const bytes = pages * 4096;
    const mb = (bytes / (1024 * 1024)).toFixed(2);
    const percent = totalRam > 0 ? ((bytes / totalRam) * 100).toFixed(2) : '0.00';
    return `${mb} MB (${percent}%)`;
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Cpu className="text-blue-500" />
          Procesos del Sistema
        </h2>
        
        <div className="flex items-center gap-3">
          {role === 'admin_user' && (
            <button
              onClick={handleToggleScan}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                scanEnabled
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'
                  : 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
              }`}
            >
              {scanEnabled ? <Power size={14} /> : <PowerOff size={14} />}
              {scanEnabled ? 'Escaneo Activo' : 'Escaneo Inactivo'}
            </button>
          )}

          {/* Barra de búsqueda */}
          <div className="relative w-full sm:w-64">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search size={16} className="text-gray-400" />
            </div>
            <input
              type="text"
              className="block w-full pl-10 pr-3 py-2 border border-gray-700 rounded-lg leading-5 bg-gray-900 text-gray-300 placeholder-gray-400 focus:outline-none focus:bg-gray-800 focus:border-blue-500 sm:text-sm transition-colors"
              placeholder="Buscar por Nombre o PID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Panel de información por PID (solo admin) */}
      {role === 'admin_user' && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 shadow-lg">
          <h3 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
            <Info size={16} className="text-blue-400" />
            Consultar Proceso por PID (Syscall 464)
          </h3>
          <form onSubmit={handleLookupPid} className="flex gap-3 items-end">
            <input
              type="number"
              value={pidLookup}
              onChange={(e) => setPidLookup(e.target.value)}
              placeholder="Ingresa un PID..."
              className="flex-1 px-4 py-2 bg-gray-950 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all"
              min="1"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Consultar
            </button>
          </form>
          {processInfo && (
            <div className="mt-4 p-4 bg-blue-500/10 border border-blue-500/30 rounded-xl text-sm">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <span className="text-gray-400 block mb-1">PID</span>
                  <span className="text-white font-mono font-bold text-lg">{processInfo.pid}</span>
                </div>
                <div>
                  <span className="text-gray-400 block mb-1">Nombre</span>
                  <span className="text-white font-medium text-lg">{processInfo.name}</span>
                </div>
                <div>
                  <span className="text-gray-400 block mb-1">Uso de Memoria</span>
                  <span className="text-white font-medium text-lg">{processInfo.memory_usage}%</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {message && (
        <div className={`p-4 rounded-lg border ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400' : 'bg-red-500/10 border-red-500/50 text-red-400'}`}>
          {message.text}
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-2xl shadow-lg overflow-hidden flex flex-col">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-800/50 border-b border-gray-800">
                <th className="p-4 text-sm font-semibold text-gray-400">PID</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Nombre</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Uso de Memoria</th>
                {role === 'admin_user' && <th className="p-4 text-sm font-semibold text-gray-400 text-right">Acciones</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {processes.map((proc, idx) => (
                <tr 
                  key={idx} 
                  onClick={() => handleRowClick(proc.pid)}
                  className="hover:bg-gray-800/50 transition-colors cursor-pointer group"
                >
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
              {processes.length === 0 && (
                <tr>
                  <td colSpan="4" className="p-8 text-center text-gray-500">No hay procesos para mostrar.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        {/* Controles de paginación */}
        <div className="bg-gray-800/30 border-t border-gray-800 p-4 flex items-center justify-between">
          <span className="text-sm text-gray-400">
            Página <span className="font-medium text-white">{page}</span> de <span className="font-medium text-white">{totalPages}</span>
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-2 rounded-lg bg-gray-800 text-gray-300 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft size={18} />
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-2 rounded-lg bg-gray-800 text-gray-300 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight size={18} />
            </button>
          </div>
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

export default Processes;
