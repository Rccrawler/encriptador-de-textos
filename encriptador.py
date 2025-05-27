from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import uuid
import sys
import tkinter as tk
from tkinter import simpledialog, messagebox

# --- CONFIGURACIÓN PREDEFINIDA ---
HARDCODED_PASSWORD = "passs"

# Ruta completa al archivo .txt que se va a gestionar (se mantiene el nombre).
# EJEMPLOS:
# Windows: HARDCODED_FILE_PATH = "C:\\Users\\TuUsuario\\Documents\\diario.txt"
# Linux/macOS: HARDCODED_FILE_PATH = "/home/TuUsuario/documentos/diario.txt"
HARDCODED_FILE_PATH = "C:\\Users\\Desktop\\harchibo.txt" # <--- ¡¡¡MODIFICA ESTA LÍNEA!!!

# --- IDENTIFICADOR ÚNICO DE MÁQUINA ---
# Obtén este valor ejecutando el script una vez con la función get_machine_id()
# y luego cópialo aquí.
# Por ejemplo: ALLOWED_MACHINE_ID = "a1:b2:c3:d4:e5:f6" (formato MAC)
# Si dejas esto como None, la comprobación de máquina se omitirá.
ALLOWED_MACHINE_ID = "00:00:00:00:00:00"
# ---------------------------------------

# Constantes del algoritmo
SALT_SIZE = 16
IV_SIZE = AES.block_size
KEY_SIZE = 32
PBKDF2_ITERATIONS = 100000
MAGIC_HEADER = b"__AES256LOCK_V2__"

# --- Funciones de GUI (Modificadas para usar solo showinfo) ---
def _show_dialog_internal(title, message):
    """Función interna para mostrar mensajes y manejar la raíz de Tkinter."""
    root = tk.Tk()
    root.withdraw()
    try:
        # Usamos showinfo para todos los tipos para intentar evitar sonidos.
        # El tipo de mensaje (error, advertencia) se indica en el título/mensaje.
        messagebox.showinfo(title, message, parent=root)
    finally:
        root.destroy()

def show_info(title, message):
    _show_dialog_internal(title, message)

def show_warning(title, message):
    # Prefijamos el título para indicar que es una advertencia
    _show_dialog_internal(f"Advertencia: {title}", message)

def show_error(title, message):
    # Prefijamos el título para indicar que es un error
    _show_dialog_internal(f"Error: {title}", message)

def ask_password(title, prompt):
    root = tk.Tk()
    root.withdraw()
    password = None
    try:
        password = simpledialog.askstring(title, prompt, show="*", parent=root)
    finally:
        root.destroy()
    return password

# --- Funciones de Lógica (sin cambios) ---
def get_machine_id():
    try:
        mac_num = uuid.getnode()
        mac = ':'.join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2))
        if mac == "00:00:00:00:00:00": return None
        return mac.lower()
    except Exception:
        return None

def verify_machine():
    if ALLOWED_MACHINE_ID is None:
        current_id_for_setup = get_machine_id()
        """
        msg = (
            "ADVERTENCIA DE CONFIGURACIÓN:\n\n"
            "No se ha configurado un ALLOWED_MACHINE_ID. "
            "La comprobación de máquina se omitirá para esta ejecución.\n\n"
            "Para configurar, copie la siguiente 'Machine ID (MAC)' "
            "en la variable 'ALLOWED_MACHINE_ID' en el código del script:\n\n"
            f"Machine ID (MAC) detectada: {current_id_for_setup if current_id_for_setup else 'No se pudo detectar ID'}"
        )"""
        # Usamos la nueva show_warning que llama a show_info
        show_warning("Configuración Requerida", msg)
        return True

    current_machine_id = get_machine_id()
    if current_machine_id and current_machine_id == ALLOWED_MACHINE_ID.lower():
        return True
    else:
        error_msg = (
            "Este script está configurado para ejecutarse solo en una máquina específica.\n\n"
            f"ID de esta máquina: {current_machine_id if current_machine_id else 'No se pudo obtener ID'}\n"
            f"ID de máquina permitida (configurada): {ALLOWED_MACHINE_ID}"
        )
        # Usamos la nueva show_error que llama a show_info
        show_error("Acceso Denegado", error_msg)
        return False

def derive_key(password_to_derive, salt):
    return PBKDF2(password_to_derive.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_file_inplace(filepath):
    try:
        with open(filepath, 'rb') as f:
            plaintext = f.read()
    except FileNotFoundError:
        show_error("Encriptación", f"El archivo '{filepath}' no fue encontrado.")
        return False
    except Exception as e:
        show_error("Encriptación", f"Error al leer el archivo '{filepath}': {e}")
        return False

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(HARDCODED_PASSWORD, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    try:
        with open(filepath, 'wb') as f:
            f.write(MAGIC_HEADER)
            f.write(salt)
            f.write(iv)
            f.write(ciphertext)
            """
        show_info("Éxito", f"Archivo '{os.path.basename(filepath)}' encriptado exitosamente.")"""
        return True
    except Exception as e:
        show_error("Encriptación", f"Error al escribir el archivo encriptado '{filepath}': {e}")
        return False

def decrypt_file_inplace(filepath, user_entered_password_check):
    if user_entered_password_check != HARDCODED_PASSWORD:
        show_error("Desencriptación", "La contraseña de verificación ingresada es incorrecta.")
        return False

    try:
        with open(filepath, 'rb') as f:
            header_check = f.read(len(MAGIC_HEADER))
            if header_check != MAGIC_HEADER:
                show_error("Desencriptación", "El archivo no parece estar encriptado por este script (cabecera mágica incorrecta).")
                return False
            salt = f.read(SALT_SIZE)
            iv = f.read(IV_SIZE)
            ciphertext = f.read()
    except FileNotFoundError:
        show_error("Desencriptación", f"El archivo '{filepath}' no fue encontrado.")
        return False
    except Exception as e:
        show_error("Desencriptación", f"Error al leer el archivo '{filepath}': {e}")
        return False

    if len(salt) != SALT_SIZE or len(iv) != IV_SIZE:
        show_error("Desencriptación", "Formato de archivo encriptado inválido (salt/iv).")
        return False

    key = derive_key(HARDCODED_PASSWORD, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        show_error("Desencriptación", "Desencriptación fallida. El archivo podría estar corrupto o la contraseña interna es incorrecta.")
        return False
    except Exception as e:
        show_error("Desencriptación", f"Error durante la operación de descifrado: {e}")
        return False

    try:
        with open(filepath, 'wb') as f:
            f.write(plaintext)
        """show_info("Éxito", f"Archivo '{os.path.basename(filepath)}' desencriptado exitosamente.")"""
        return True
    except Exception as e:
        show_error("Desencriptación", f"Error al escribir el archivo desencriptado '{filepath}': {e}")
        return False

def is_file_content_encrypted(filepath):
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return False
    try:
        with open(filepath, 'rb') as f:
            header = f.read(len(MAGIC_HEADER))
        return header == MAGIC_HEADER
    except Exception:
        return False

if __name__ == "__main__":
    if not verify_machine():
        sys.exit(1)

    file_path = HARDCODED_FILE_PATH

    if not os.path.exists(file_path):
        show_error("Archivo", f"El archivo especificado:\n'{file_path}'\nno existe.")
        sys.exit(1)
    
    if not file_path.lower().endswith(".txt"):
        show_warning("Archivo",
                       f"El archivo:\n'{os.path.basename(file_path)}'\n"
                       "no tiene extensión .txt, pero se procederá.")

    if is_file_content_encrypted(file_path):
        """show_info("Estado del Archivo", f"El archivo '{os.path.basename(file_path)}' parece estar encriptado.")"""
        user_password_attempt = ask_password("Verificación de Contraseña", "Para desencriptar, introduce la contraseña:")
        
        if user_password_attempt is None:
            """show_info("Operación Cancelada", "Desencriptación cancelada por el usuario.")"""
        elif not user_password_attempt:
            # Usamos la nueva show_warning
            show_warning("Entrada Inválida", "La contraseña de verificación no puede ser vacía.")
        else:
            decrypt_file_inplace(file_path, user_password_attempt)
    else:
        """show_info("Estado del Archivo", f"El archivo '{os.path.basename(file_path)}' no está encriptado o no tiene la cabecera correcta.\nProcediendo a encriptar...")"""
        encrypt_file_inplace(file_path)

    sys.exit(0) # Asegura explícitamente que el programa termina.
