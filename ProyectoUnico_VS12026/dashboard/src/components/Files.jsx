import { useState, useEffect } from 'react';
import axios from 'axios';
import { FileSearch, ShieldCheck, ShieldAlert, Power, PowerOff, Shield } from 'lucide-react';

const Files = ({ role }) => {
  const [files, setFiles] = useState([]);
  const [scanEnabled, setScanEnabled] = useState(true);
  const [message, setMessage] = useState(null);
  const [quarantineFile, setQuarantineFile] = useState('');

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

  // Obtener archivos escaneados
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/files`);
        if (Array.isArray(res.data)) {
          setFiles(res.data);
        }
      } catch (err) {
        console.error("Error fetching files:", err);
      }
    };
    fetchFiles();
    const interval = setInterval(fetchFiles, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleScan = async () => {
    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/toggle_scan`);
      setScanEnabled(res.data.scan_enabled);
    } catch (err) { console.error(err); }
  };

  const handleQuarantine = async (filename) => {
    const confirmed = window.confirm(`¿Deseas poner en cuarentena el archivo "${filename}"?\n\nSe revocarán todos los permisos de acceso y ejecución.`);
    if (!confirmed) return;

    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/quarantine?file=${encodeURIComponent(filename)}`);
      if (res.data.status === 'success') {
        setMessage({ type: 'success', text: `Archivo '${filename}' puesto en cuarentena exitosamente.` });
      } else {
        setMessage({ type: 'error', text: res.data.message || 'Error al poner en cuarentena.' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Error de red o servidor.' });
    }
    setTimeout(() => setMessage(null), 4000);
  };

  const maliciousCount = files.filter(f => f.is_malicious).length;
  const cleanCount = files.filter(f => !f.is_malicious).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <FileSearch className="text-cyan-500" />
          Archivos Analizados
        </h2>

        {role === 'admin_user' && (
          <button
            onClick={handleToggleScan}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              scanEnabled
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'
                : 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
            }`}
          >
            {scanEnabled ? <Power size={14} /> : <PowerOff size={14} />}
            {scanEnabled ? 'Escaneo Activo' : 'Escaneo Inactivo'}
          </button>
        )}
      </div>

      {/* Resumen */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-cyan-500/20 text-cyan-400 rounded-lg"><FileSearch size={24} /></div>
          <div>
            <p className="text-2xl font-bold text-white">{files.length}</p>
            <p className="text-xs text-gray-400">Archivos Escaneados</p>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-emerald-500/20 text-emerald-400 rounded-lg"><ShieldCheck size={24} /></div>
          <div>
            <p className="text-2xl font-bold text-emerald-400">{cleanCount}</p>
            <p className="text-xs text-gray-400">Archivos Limpios</p>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-red-500/20 text-red-400 rounded-lg"><ShieldAlert size={24} /></div>
          <div>
            <p className="text-2xl font-bold text-red-400">{maliciousCount}</p>
            <p className="text-xs text-gray-400">Archivos Infectados</p>
          </div>
        </div>
      </div>

      {message && (
        <div className={`p-4 rounded-lg border ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400' : 'bg-red-500/10 border-red-500/50 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* Tabla de archivos */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-800/50 border-b border-gray-800">
                <th className="p-4 text-sm font-semibold text-gray-400">Archivo</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Estado</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Hash SHA-256</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Última Modificación</th>
                {role === 'admin_user' && <th className="p-4 text-sm font-semibold text-gray-400 text-right">Acciones</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {files.length === 0 ? (
                <tr>
                  <td colSpan={role === 'admin_user' ? 5 : 4} className="p-8 text-center text-gray-500">
                    No se han escaneado archivos aún. Crea o modifica archivos en <code className="text-blue-400 bg-gray-950 px-2 py-0.5 rounded">/home/sopes/monitor/</code>
                  </td>
                </tr>
              ) : (
                files.map((file, idx) => (
                  <tr key={idx} className="hover:bg-gray-800/20 transition-colors">
                    <td className="p-4 text-white font-medium">{file.filename}</td>
                    <td className="p-4">
                      {file.is_quarantined ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                          <ShieldAlert size={12} /> Cuarentena
                        </span>
                      ) : file.is_malicious ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                          <ShieldAlert size={12} /> Infectado
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          <ShieldCheck size={12} /> Benigno
                        </span>
                      )}
                    </td>
                    <td className="p-4 text-gray-400 font-mono text-xs max-w-[200px] truncate" title={file.hash}>{file.hash}</td>
                    <td className="p-4 text-gray-500 text-sm font-mono">{file.timestamp}</td>
                    {role === 'admin_user' && (
                      <td className="p-4 text-right">
                        <button
                          onClick={() => handleQuarantine(file.filename)}
                          disabled={file.is_quarantined}
                          className={`p-2 flex items-center justify-center ml-auto gap-1.5 text-xs rounded-lg transition-colors ${
                            file.is_quarantined
                              ? 'text-gray-600 bg-gray-800 cursor-not-allowed'
                              : 'text-orange-400 hover:text-orange-300 hover:bg-orange-500/10'
                          }`}
                          title={file.is_quarantined ? "Ya está en cuarentena" : "Poner en cuarentena"}
                        >
                          <Shield size={14} /> Cuarentena
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Files;
