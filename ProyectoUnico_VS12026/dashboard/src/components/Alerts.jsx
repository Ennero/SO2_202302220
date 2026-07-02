/**
 * Alerts.jsx - Componente del panel de alertas de seguridad
 * 
 * Muestra el registro cronológico de todas las alertas generadas por el sistema.
 * Las alertas se diferencian visualmente por color según su severidad:
 *   - HIGH   → Rojo (amenaza crítica: hash malicioso, archivo en cuarentena)
 *   - MEDIUM → Amarillo (advertencia: login fallido, proceso matado, BD actualizada)
 *   - LOW    → Azul (informativo: archivo limpio, login exitoso, monitoreo activado)
 * 
 * Las alertas llegan ordenadas del backend (más recientes primero).
 * Este componente recibe las alertas como prop desde Dashboard.jsx,
 * que las obtiene cada 2 segundos del endpoint GET /api/alerts.
 */
import { ShieldAlert, AlertTriangle, Info } from 'lucide-react';

const Alerts = ({ alerts }) => {
  /**
   * getSeverityStyle - Determina los estilos visuales según la severidad
   * 
   * Cada nivel de severidad tiene su propio color y ícono para que
   * el usuario pueda identificar rápidamente la importancia de cada alerta.
   * 
   * @param {string} severity - Nivel de severidad: "HIGH", "MEDIUM", o "LOW"
   * @returns {object} Objeto con clases CSS y componente del ícono
   */
  /**
   * getSeverityStyle - Determina los estilos visuales según la severidad
   * getSeverityLabel - Traduce la severidad a un texto legible en español
   */
  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'HIGH':
        return {
          bg: 'bg-red-500/10',           // Fondo rojo semitransparente
          border: 'border-red-500/50',    // Borde rojo
          text: 'text-red-400',           // Texto rojo
          icon: <ShieldAlert size={20} />, // Ícono de escudo con alerta
          label: 'ALTO',
          labelBg: 'bg-red-500/20 border-red-500/40 text-red-400',
        };
      case 'MEDIUM':
        return {
          bg: 'bg-yellow-500/10',
          border: 'border-yellow-500/50',
          text: 'text-yellow-400',
          icon: <AlertTriangle size={20} />,
          label: 'MEDIO',
          labelBg: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-400',
        };
      case 'LOW':
      default:
        return {
          bg: 'bg-blue-500/10',
          border: 'border-blue-500/50',
          text: 'text-blue-400',
          icon: <Info size={20} />,
          label: 'BAJO',
          labelBg: 'bg-blue-500/20 border-blue-500/40 text-blue-400',
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Encabezado de la sección */}
      <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
        <ShieldAlert className="text-red-500" />
        Registro de Alertas de Seguridad
      </h2>

      {/* Lista de alertas */}
      <div className="space-y-4">
        {alerts.length === 0 ? (
          /* Mensaje cuando no hay alertas */
          <div className="p-8 text-center text-gray-500 bg-gray-900 border border-gray-800 rounded-2xl">
            No se han registrado alertas recientes.
          </div>
        ) : (
          /* Renderizamos cada alerta con su estilo correspondiente */
          alerts.map((alert, idx) => {
            const style = getSeverityStyle(alert.severidad);
            return (
              <div 
                key={idx} 
                className={`p-4 rounded-xl border ${style.bg} ${style.border} flex items-start gap-4 transition-all hover:bg-opacity-20`}
              >
                {/* Ícono de severidad */}
                <div className={`mt-1 ${style.text}`}>
                  {style.icon}
                </div>
                {/* Contenido de la alerta */}
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    {/* Tipo de evento y badge de severidad */}
                    <div className="flex items-center gap-2">
                      <h4 className={`font-semibold ${style.text} uppercase tracking-wider text-sm`}>
                        {alert.tipo}
                      </h4>
                      {/* Badge con el nivel de severidad en texto */}
                      <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full border ${style.labelBg}`}>
                        {style.label}
                      </span>
                    </div>
                    {/* Fecha y hora del evento */}
                    <span className="text-xs text-gray-500 font-mono bg-gray-950 px-2 py-1 rounded shrink-0">
                      {alert.fecha}
                    </span>
                  </div>
                  {/* Descripción detallada de la alerta */}
                  <p className="text-gray-300">
                    {alert.descripcion}
                  </p>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default Alerts;
