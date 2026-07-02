# =============================================================
# Makefile - Compilación del Daemon EDR Híbrido
#
# Este Makefile automatiza la compilación del programa intermedio.
# Para compilar: make
# Para limpiar:  make clean
#
# Dependencias necesarias (instalar con apt):
#   sudo apt install libpam0g-dev libssl-dev libjansson-dev
# =============================================================

# Compilador de C
CC = gcc

# Flags de compilación:
#   -Wall    = Activar todas las advertencias (buena práctica)
#   -pthread = Habilitar soporte para hilos POSIX (pthreads)
CFLAGS = -Wall -pthread

# Librerías que necesitamos enlazar:
#   -lssl -lcrypto = OpenSSL (para calcular hashes SHA-256)
#   -ljansson      = Jansson (para crear y parsear JSON)
#   -lpam          = PAM (para autenticar usuarios del sistema)
LDFLAGS = -lssl -lcrypto -ljansson -lpam

# Lista de archivos fuente (.c) que componen el programa
SRCS = main.c metrics.c alerts.c scanner.c auth.c http_server.c

# Generamos automáticamente los nombres de los archivos objeto (.o)
# Ejemplo: main.c -> main.o, metrics.c -> metrics.o, etc.
OBJS = $(SRCS:.c=.o)

# Nombre del ejecutable final
TARGET = daemon_monitor

# Regla principal: compilar el ejecutable
all: $(TARGET)

# Regla para generar el ejecutable a partir de los archivos objeto
# El compilador enlaza todos los .o junto con las librerías (-l)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Regla genérica: compilar cada .c a .o
# $< = archivo fuente (.c), $@ = archivo destino (.o)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Limpieza: eliminar archivos compilados
clean:
	rm -f $(OBJS) $(TARGET)
