import { useState, useEffect } from 'react';
import axios from 'axios';
import { Bug, Upload, AlertTriangle, FileWarning, Database, Download, PlusCircle, RefreshCw } from 'lucide-react';

const Threats = ({ role }) => {
  const [files, setFiles] = useState([]);
  const [message, setMessage] = useState(null);
  const [uploadText, setUploadText] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMode, setUploadMode] = useState('append'); // 'append' o 'replace'

  // Obtener archivos escaneados y filtrar solo las amenazas
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/files`);
        if (Array.isArray(res.data)) {
          setFiles(res.data.filter(f => f.is_malicious && !f.is_quarantined));
        }
      } catch (err) {
        console.error("Error fetching threats:", err);
      }
    };
    fetchFiles();
    const interval = setInterval(fetchFiles, 1000);
    return () => clearInterval(interval);
  }, []);

  // Subir actualización de blacklist
  const handleUploadBlacklist = async (e) => {
    e.preventDefault();
    if (!uploadText.trim()) return;

    setIsUploading(true);
    try {
      // Validar que sea JSON válido antes de enviar
      const parsed = JSON.parse(uploadText);

      // Validar estructura
      for (const [key, value] of Object.entries(parsed)) {
        if (!value.hash || !value.descripcion) {
          setMessage({ type: 'error', text: `Entrada "${key}" no tiene los campos "hash" y "descripcion" requeridos.` });
          setIsUploading(false);
          setTimeout(() => setMessage(null), 5000);
          return;
        }
      }

      const endpoint = uploadMode === 'replace' ? 'update_blacklist' : 'add_blacklist';
      const res = await axios.post(
        `http://${window.location.hostname}:8080/api/${endpoint}`,
        uploadText,
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (res.data.status === 'success') {
        setMessage({ type: 'success', text: `Base de datos de hashes ${uploadMode === 'replace' ? 'reemplazada' : 'actualizada'} exitosamente.` });
        setUploadText('');
      } else {
        setMessage({ type: 'error', text: res.data.message || 'Error al actualizar.' });
      }
    } catch (err) {
      if (err instanceof SyntaxError) {
        setMessage({ type: 'error', text: 'El contenido no es JSON válido. Verifica la sintaxis.' });
      } else {
        setMessage({ type: 'error', text: 'Error de red o servidor al actualizar la blacklist.' });
      }
    }
    setIsUploading(false);
    setTimeout(() => setMessage(null), 5000);
  };

  // Manejar carga de archivo
  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
      setMessage({ type: 'error', text: 'Solo se permiten archivos con formato JSON (.json).' });
      setTimeout(() => setMessage(null), 4000);
      return;
    }

    const reader = new FileReader();
    reader.onload = (ev) => {
      setUploadText(ev.target.result);
    };
    reader.readAsText(file);
  };

  const handleDownloadBlacklist = () => {
    window.open(`http://${window.location.hostname}:8080/api/download_blacklist`, '_blank');
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-white flex items-center gap-3 mb-6">
        <Bug className="text-red-500" />
        Amenazas Detectadas
      </h2>

      {/* Resumen */}
      <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl shadow-lg flex items-center gap-4">
        <div className="p-3 bg-red-500/20 text-red-400 rounded-xl">
          <AlertTriangle size={28} />
        </div>
        <div>
          <p className="text-3xl font-bold text-red-400">{files.length}</p>
          <p className="text-sm text-gray-400">Amenazas detectadas por comparación de firmas SHA-256</p>
        </div>
      </div>

      {message && (
        <div className={`p-4 rounded-lg border ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400' : 'bg-red-500/10 border-red-500/50 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* Lista de amenazas */}
      <div className="space-y-3">
        {files.length === 0 ? (
          <div className="p-8 text-center text-gray-500 bg-gray-900 border border-gray-800 rounded-2xl">
            No se han detectado amenazas. El sistema está limpio.
          </div>
        ) : (
          files.map((file, idx) => (
            <div key={idx} className="bg-gray-900 border border-red-500/30 rounded-xl p-5 hover:border-red-500/50 transition-all">
              <div className="flex items-start gap-4">
                <div className="mt-1 p-2 bg-red-500/20 text-red-400 rounded-lg">
                  <FileWarning size={20} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-red-400 font-bold text-sm uppercase tracking-wider">
                      {file.threat_name || 'Amenaza desconocida'}
                    </h4>
                    <span className="text-xs text-gray-500 font-mono bg-gray-950 px-2 py-1 rounded shrink-0">
                      {file.timestamp}
                    </span>
                  </div>
                  <p className="text-white font-medium mb-1">
                    Archivo: <span className="text-orange-300">{file.filename}</span>
                  </p>
                  <p className="text-gray-400 text-sm mb-2">{file.description}</p>
                  <p className="text-gray-500 text-xs font-mono break-all">
                    SHA-256: {file.hash}
                  </p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Panel para actualizar blacklist (solo admin) */}
      {role === 'admin_user' && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-xl">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-medium text-white flex items-center gap-2">
              <Database size={20} className="text-purple-400" />
              Gestión de Base de Datos (Blacklist)
            </h3>
            <button
              onClick={handleDownloadBlacklist}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600/20 text-blue-400 border border-blue-500/30 hover:bg-blue-600/30 rounded-lg text-sm transition-colors"
              title="Descargar Blacklist Actual"
            >
              <Download size={16} />
              Descargar JSON Actual
            </button>
          </div>
          <p className="text-gray-400 text-sm mb-4">
            Sube un archivo JSON o pega el contenido directamente. El formato debe contener entradas con los campos <code className="text-blue-400 bg-gray-950 px-1 rounded">hash</code> y <code className="text-blue-400 bg-gray-950 px-1 rounded">descripcion</code>.
          </p>
          
          <div className="flex gap-4 mb-4">
            <button
              type="button"
              onClick={() => setUploadMode('append')}
              className={`flex-1 py-2 px-4 rounded-lg flex items-center justify-center gap-2 text-sm font-medium transition-colors ${
                uploadMode === 'append'
                  ? 'bg-purple-600 text-white shadow-lg'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              <PlusCircle size={16} /> Añadir Amenazas (Recomendado)
            </button>
            <button
              type="button"
              onClick={() => setUploadMode('replace')}
              className={`flex-1 py-2 px-4 rounded-lg flex items-center justify-center gap-2 text-sm font-medium transition-colors ${
                uploadMode === 'replace'
                  ? 'bg-red-600 text-white shadow-lg'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              <RefreshCw size={16} /> Reemplazar Blacklist
            </button>
          </div>

          {/* Subir archivo */}
          <div className="mb-4">
            <label className="block">
              <span className="sr-only">Seleccionar archivo JSON</span>
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleFileUpload}
                className="block w-full text-sm text-gray-400
                  file:mr-4 file:py-2 file:px-4
                  file:rounded-lg file:border file:border-gray-700
                  file:text-sm file:font-medium
                  file:bg-gray-800 file:text-gray-300
                  hover:file:bg-gray-700 file:transition-colors
                  file:cursor-pointer cursor-pointer"
              />
            </label>
          </div>

          <form onSubmit={handleUploadBlacklist} className="space-y-4">
            <textarea
              value={uploadText}
              onChange={(e) => setUploadText(e.target.value)}
              placeholder={'{\n  "NombreAmenaza": {\n    "hash": "sha256_hash_aqui",\n    "descripcion": "Descripcion de la amenaza"\n  }\n}'}
              className="w-full h-40 px-4 py-3 bg-gray-950 border border-gray-700 rounded-xl text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all resize-none"
              spellCheck="false"
            />
            <button
              type="submit"
              disabled={isUploading || !uploadText.trim()}
              className={`w-full flex items-center justify-center gap-2 py-3 px-4 disabled:cursor-not-allowed text-white rounded-xl font-medium shadow-lg transition-colors ${
                uploadMode === 'replace' 
                  ? 'bg-red-600 hover:bg-red-700 disabled:bg-red-900' 
                  : 'bg-purple-600 hover:bg-purple-700 disabled:bg-purple-900'
              }`}
            >
              <Upload size={18} />
              {isUploading ? 'Procesando...' : (uploadMode === 'replace' ? 'Reemplazar Blacklist' : 'Añadir a Blacklist')}
            </button>
          </form>
        </div>
      )}
    </div>
  );
};

export default Threats;
