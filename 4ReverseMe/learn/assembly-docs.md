# GDB x86 Assembly Instruction Guide

Este documento explica las instrucciones de ensamblador x86 comunes vistas en el desensamblado de GDB, enfocándose en su operación y cómo manipulan direcciones y datos.

## 1. Instrucciones de Transferencia de Datos

| Instrucción | Ejemplo | Explicación | Cómo funciona con direcciones |
|-------------|---------|-------------|-------------------------------|
| `mov` | `mov %eax, %esi` | Copia datos de origen a destino | Puede mover datos entre registros, o entre memoria y registros. El operando con `(%reg)` es una dirección de memoria. |
| `mov` | `mov 0x4(%eax), %eax` | Desreferencia un puntero | 1. Toma el valor en `%eax`<br>2. Le suma 4<br>3. Va a esa dirección resultante<br>4. Copia el valor de 4 bytes de esa dirección a `%eax` |
| `mov` | `mov %eax, 0x28(%esp)` | Almacena un valor en el stack | Calcula la dirección `%esp + 0x28` y almacena el valor de `%eax` ahí |
| `push` | `push %ebp` | Decrementa `%esp` y almacena el operando en la nueva ubicación | `push %ebp` es equivalente a:<br>`sub $4, %esp`<br>`mov %ebp, (%esp)` |
| `pop` | `pop %edi` | Carga el valor en `(%esp)` al operando y luego incrementa `%esp` | El inverso de push. Usado para restaurar valores de registros guardados del stack |

## 2. Instrucciones Aritméticas y Lógicas

| Instrucción | Ejemplo | Explicación | Cómo funciona con direcciones |
|-------------|---------|-------------|-------------------------------|
| `add` | `add $0x12e10, %ebx` | Suma el operando origen al destino | `%ebx = %ebx + 0x12e10`. Usado para ajustar punteros o calcular offsets |
| `add` | `add 0x4(%eax), %edx` | Suma el valor en la dirección de memoria `%eax+4` al registro `%edx` | `%edx = %edx + *(uint32_t *)(%eax + 4)` |
| `sub` | `sub $0x4c, %esp` | Asigna espacio en el stack | Resta 76 bytes (0x4c) del stack pointer. Crea espacio para variables locales |
| `shr` | `shr $0x8, %edi` | Shift Right | `%edi = %edi >> 8`. Usado para máscaras de bits y extraer campos específicos |
| `shl` | `shl $0x4, %ecx` | Shift Left | `%ecx = %ecx << 4`. Equivalente a multiplicar por 16 |
| `and` | `and $0x3, %ebp` | AND bitwise | Pone a cero todos los bits en `%ebp` excepto los dos menos significativos |
| `xor` | `xor %edx, %edx` | XOR bitwise | `%edx XOR %edx` siempre es 0. Más rápido que `mov $0, %edx` |
| `test` | `test %eax, %eax` | Realiza AND bitwise pero solo establece flags | Usado para verificar si un valor es cero o negativo |

## 3. Instrucciones de Flujo de Control

| Instrucción | Ejemplo | Explicación |
|-------------|---------|-------------|
| `call` | `call 0xb7ff6bab` | Empuja la dirección de retorno en el stack y salta a la dirección objetivo |
| `jmp` | `jmp 0xb7fec2ea` | Salto incondicional |
| `jne` | `jne 0xb7fec358` | Salto si no es igual (ZF == 0) |
| `je` | `je 0xb7fec256` | Salto si es igual (ZF == 1) |
| `cmp` | `cmp $0x7, %al` | Compara. Resta origen de destino y establece flags |

## 4. Instrucciones Especiales y Manipulación de Datos

| Instrucción | Ejemplo | Explicación |
|-------------|---------|-------------|
| `lea` | `lea 0x3c(%esp), %ecx` | Load Effective Address. Calcula la dirección del operando origen | `%ecx = %esp + 0x3c` (como `&` en C) |
| `movzbl` | `movzbl 0xd(%ecx), %ebp` | Move with Zero-Extend, Byte to Long | Lee un byte de `%ecx + 0xd` y lo extiende a 32 bits |
| `cmove` | `cmove %ebp, %edx` | Conditional Move (if Equal) | Si ZF está establecido, realiza `mov %ebp, %edx` |

## 5. Modos de Direccionamiento Explicados

### Inmediato
```assembly
$0x4c    # Un valor literal: 76
```

### Registro
```assembly
%eax     # El valor dentro del registro
```

### Directo
```assembly
0x804a024    # El valor en esta dirección de memoria fija
```

### Indirecto
```assembly
(%eax)       # El valor en la dirección de memoria almacenada en %eax
```

### Desplazado (Base+Offset)
```assembly
0x28(%esp)   # El valor en la dirección calculada por %esp + 0x28
```

### Indexado
```assembly
(%eax,%edi,2)    # El valor en la dirección calculada por %eax + (%edi * 2)
```

## Comandos de GDB para Trabajar con Esto

### Desensamblado
```bash
disassemble /r                    # Desensambla la función actual mostrando opcodes
disassemble $pc, +20             # Desensambla 20 instrucciones desde PC
```

### Registros y Memoria
```bash
info registers                   # Imprime todos los valores de registros
x/xw $esp                       # Examina memoria: 1 palabra (4 bytes) en hex
x/10xw $esp                     # Muestra 10 palabras en el stack
x/s 0x804a024                   # Examina memoria e intenta imprimirla como string
```

### Ejecución Paso a Paso
```bash
stepi (si)                      # Ejecuta una instrucción de ensamblador, entrando en llamadas
nexti (ni)                      # Ejecuta una instrucción de ensamblador, saltando llamadas
```

### Breakpoints
```bash
break *0xb7fec1e4               # Establece breakpoint en una dirección específica
```

## Sesión de Debugging de Ejemplo

```bash
(gdb) break main
(gdb) run
(gdb) disassemble /r
... ver una instrucción como mov 0x4(%eax), %eax ...
(gdb) info registers eax
eax            0x804c850   134529104  # Digamos que %eax apunta a 0x804c850
(gdb) x/xw 0x804c850      # Mirar el valor en esa dirección
0x804c850:      0x0804c864
(gdb) x/xw 0x804c850 + 4  # Ahora mirar el valor en *(%eax + 4)
0x804c854:      0x0000000a           # Este es el valor que se moverá a %eax
(gdb) stepi
(gdb) info registers eax
eax            0xa  10               # %eax ahora contiene el valor 10 (0xa)
```

## Resumen de Patrones Comunes

### Inicialización de Registros
```assembly
xor %eax, %eax    # Poner %eax a 0 (más eficiente que mov $0, %eax)
mov $0, %ebx      # Poner %ebx a 0 (alternativa)
```

### Acceso a Variables Locales
```assembly
mov 0x28(%esp), %eax    # Cargar variable local en %eax
mov %ebx, 0x2c(%esp)    # Almacenar %ebx en variable local
```

### Aritmética de Punteros
```assembly
add $4, %eax      # Incrementar puntero en 4 bytes
add $1, %edi      # Incrementar índice de array
```

### Comparaciones y Saltos
```assembly
cmp $0, %eax      # Comparar %eax con 0
je label          # Saltar si es igual (zero flag set)
jne label         # Saltar si no es igual (zero flag clear)
```

## Consejos para Debugging

1. **Siempre verifica registros después de cada paso**: `info registers`
2. **Examina memoria cuando veas direcciones**: `x/xw address`
3. **Usa `/r` en disassemble para ver opcodes**: `disassemble /r`
4. **Sigue el flujo de datos**: rastrea cómo se mueven los datos entre registros y memoria
5. **Presta atención a los offsets**: `0x28(%esp)` significa 40 bytes desde el stack pointer

---

*Este documento es una guía de referencia rápida para entender el ensamblador x86 en el contexto de debugging con GDB.*
