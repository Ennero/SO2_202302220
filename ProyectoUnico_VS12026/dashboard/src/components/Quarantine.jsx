import { useState, useEffect } from 'react';
import { FileWarning, Shield, Lock, FolderLock } from 'lucide-react';
import axios from 'axios';

const Quarantine = ({ role }) => {
  const [filename, setFilename] = useState('');
  const [message, setMessage] = useState(null);
  const [quarantinedFiles, setQuarantinedFiles] = useState([]);

  // Obtener archivos en cuarentena
  useEffect(() => {
    const fetchQuarantined = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/quarantine_list`);
        if (Array.isArray(res.data)) {
          setQuarantinedFiles(res.data);
        }
      } catch (err) {
        console.error("Error fetching quarantine list:", err);
      }
    };
    fetchQuarantined();
    const interval = setInterval(fetchQuarantined, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!filename.trim()) return;

    const confirmed = window.confirm(
      `¿Estás seguro de poner en cuarentena el archivo "${filename}"?\n\nSe revocarán TODOS los permisos (chmod 0000).`
    );
    if (!confirmed) return;

    try {
      const res = await axios.get(`http://${window.location.hostname}:8080/api/quarantine?file=${encodeURIComponent(filename)}`);
      if (res.data.status === 'success') {
        setMessage({ type: 'success', text: `Archivo '${filename}' puesto en cuarentena exitosamente.` });
        setFilename('');
      } else {
        setMessage({ type: 'error', text: res.data.message || 'Error al poner en cuarentena el archivo.' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Error de red o de servidor.' });
    }
    
    setTimeout(() => setMessage(null), 5000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 mb-8">
        <div className="p-4 bg-orange-500/20 text-orange-500 rounded-2xl">
          <FileWarning size={32} />
        </div>
        <div>
          <h2 className="text-2xl font-bold text-white">Cuarentena de Archivos</h2>
          <p className="text-gray-400">Gestión y bloqueo preventivo de archivos sospechosos</p>
        </div>
      </div>

      {message && (
        <div className={`p-4 rounded-xl border ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400' : 'bg-red-500/10 border-red-500/50 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* Formulario para agregar archivo (solo admin) */}
      {role === 'admin_user' && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 shadow-xl">
          <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
            <Shield size={20} className="text-orange-400" />
            Agregar Archivo a Cuarentena
          </h3>
          <p className="text-gray-300 mb-6">
            Ingresa el nombre del archivo (ubicado en <code className="text-blue-400 bg-gray-950 px-2 py-1 rounded">/home/sopes/monitor/</code>) 
            para revocarle todos los permisos de acceso y ejecución.
          </p>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Nombre del Archivo</label>
              <input
                type="text"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                placeholder="ej. malware.bin"
                className="w-full px-4 py-3 bg-gray-950 border border-gray-700 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-orange-500 transition-all"
                required
              />
            </div>

            <button
              type="submit"
              className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-medium shadow-lg transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 focus:ring-offset-gray-900"
            >
              <Shield size={20} />
              Aplicar Cuarentena (chmod 0000)
            </button>
          </form>
        </div>
      )}

      {/* Lista de archivos en cuarentena */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl shadow-lg overflow-hidden">
        <div className="p-6 border-b border-gray-800">
          <h3 className="text-lg font-medium text-white flex items-center gap-2">
            <FolderLock size={20} className="text-orange-400" />
            Archivos en Cuarentena ({quarantinedFiles.length})
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-800/50 border-b border-gray-800">
                <th className="p-4 text-sm font-semibold text-gray-400 w-12">#</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Archivo</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Permisos</th>
                <th className="p-4 text-sm font-semibold text-gray-400">Fecha de Cuarentena</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {quarantinedFiles.length === 0 ? (
                <tr>
                  <td colSpan="4" className="p-8 text-center text-gray-500">
                    No hay archivos en cuarentena.
                  </td>
                </tr>
              ) : (
                quarantinedFiles.map((file, idx) => (
                  <tr key={idx} className="hover:bg-gray-800/20 transition-colors">
                    <td className="p-4 text-gray-500 font-mono text-sm">{idx + 1}</td>
                    <td className="p-4 text-white font-medium flex items-center gap-2">
                      <Lock size={14} className="text-orange-400" />
                      {file.filename}
                    </td>
                    <td className="p-4">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                        0000
                      </span>
                    </td>
                    <td className="p-4 text-gray-500 text-sm font-mono">{file.timestamp}</td>
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

export default Quarantine;
