import React from 'react';
import { X, Info, AlertCircle, Loader2 } from 'lucide-react';

/**
 * ProcessModal.jsx - Ventana emergente (Modal) para mostrar info de un proceso
 * 
 * Este componente recibe un 'pid' y hace una petición GET /api/process_info?pid=X
 * para obtener y mostrar la información devuelta por la syscall 464.
 */
const ProcessModal = ({ pid, processInfo, error, isLoading, onClose }) => {
  if (!pid) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-950/80 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-200">
        
        {/* Encabezado del modal */}
        <div className="flex items-center justify-between p-4 border-b border-gray-800 bg-gray-800/50">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Info className="text-blue-400" size={20} />
            Detalles del Proceso
          </h3>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-white hover:bg-gray-700 p-1.5 rounded-lg transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Contenido del modal */}
        <div className="p-6">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-8 space-y-3">
              <Loader2 className="animate-spin text-blue-500" size={32} />
              <p className="text-gray-400 text-sm">Obteniendo información del kernel...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-6 space-y-3 text-red-400">
              <AlertCircle size={40} className="opacity-80" />
              <p className="text-center font-medium">{error}</p>
            </div>
          ) : processInfo ? (
            <div className="space-y-4">
              <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl">
                <span className="text-gray-500 text-xs font-semibold uppercase tracking-wider block mb-1">Nombre</span>
                <span className="text-white text-lg font-medium">{processInfo.name}</span>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl">
                  <span className="text-gray-500 text-xs font-semibold uppercase tracking-wider block mb-1">PID</span>
                  <span className="text-blue-400 font-mono text-xl">{processInfo.pid}</span>
                </div>
                
                <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl">
                  <span className="text-gray-500 text-xs font-semibold uppercase tracking-wider block mb-1">Uso de Memoria</span>
                  <span className="text-emerald-400 font-mono text-xl">{processInfo.memory_usage}%</span>
                </div>
              </div>
              
              <p className="text-xs text-gray-500 text-center mt-4">
                Información obtenida a través de la syscall sys_get_process_info (464)
              </p>
            </div>
          ) : (
            <div className="text-center text-gray-500">No hay información disponible.</div>
          )}
        </div>
        
        {/* Footer del modal */}
        <div className="p-4 border-t border-gray-800 bg-gray-800/30 flex justify-end">
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors text-sm"
          >
            Cerrar
          </button>
        </div>

      </div>
    </div>
  );
};

export default ProcessModal;
