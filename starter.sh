#!/bin/bash
#El objetivo de este script es bajar la tabla BGP IPv6 de Potaroo
#Chequear con un basic sanity check que el archivo se haya bajado bien revisando el stderr del wget
#y finalmente revisa si el archivo tiene un tamano normal (entre 90 y 300 MB)
#Si todo va bien ejecuta el script de python que envia el IPv6 Weekly Report por email
#El script aborta con staderr de 1 en caso de que falle
TODAY=`date +%Y%m%d`
LOGFILE="ipv6weeklyreportbyemail.log" #LOGFILE

#Just a small log
echo "     -------- ////// ------    " >> $LOGFILE
echo "Starting script on `date`" >> $LOGFILE

# Config
URL1="https://bgp.potaroo.net/v6/as2.0/bgptable.txt"  # bgptable de potarro correspondiente a IPv6
URL2="https://www.nro.net/wp-content/uploads/apnic-uploads/delegated-extended"
URL3="https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv"
FILE1="bgptable.txt"
FILE2="delegated-extended"
FILE3="ipv6-unicast-address-assignments.csv"
MIN_SIZE1=90000000      # 90 MB
MAX_SIZE1=299955950     # ~300 MB
MIN_SIZE2=45000000      # 45 MB
MAX_SIZE2=149955950     # ~150 MB
MIN_SIZE3=4600      # 4600 bytes
MAX_SIZE3=6000     # 6000 bytes
TEMP_FILE1="${FILE1}.tmp"
TEMP_FILE2="${FILE2}.tmp"
TEMP_FILE3="${FILE3}.tmp"

rm -f bgptable.txt #delete any old bgptable.txt
rm -f delegated-extended #delete any old bgptable.txt
rm -f ipv6-unicast-address-assignments.csv #delete any old iana file

# Funciones para validar tamaño
validate_size1() {
    local file="$1"
    local size=$(stat -c%s "$file" 2>/dev/null || wc -c <"$file")

    if [ "$size" -lt "$MIN_SIZE1" ]; then
        echo "  ERROR: El archivo es demasiado pequeño ($size bytes)"
        return 1
    elif [ "$size" -gt "$MAX_SIZE1" ]; then
        echo "  ERROR: El archivo es demasiado grande ($size bytes)"
        return 1
    else
        echo "  VALIDACIÓN EXITOSA: Tamaño correcto ($size bytes) `date`"
        return 0
    fi
}

validate_size2() {
    local file="$1"
    local size=$(stat -c%s "$file" 2>/dev/null || wc -c <"$file")

    if [ "$size" -lt "$MIN_SIZE2" ]; then
        echo "  ERROR: El archivo es demasiado pequeño ($size bytes)"
        return 1
    elif [ "$size" -gt "$MAX_SIZE2" ]; then
        echo "  ERROR: El archivo es demasiado grande ($size bytes)"
        return 1
    else
        echo "  VALIDACIÓN EXITOSA: Tamaño correcto ($size bytes) `date`"
        return 0
    fi
}

validate_size3() {
    local file="$1"
    local size=$(stat -c%s "$file" 2>/dev/null || wc -c <"$file")

    if [ "$size" -lt "$MIN_SIZE3" ]; then
        echo "  ERROR: El archivo es demasiado pequeño ($size bytes)"
        return 1
    elif [ "$size" -gt "$MAX_SIZE3" ]; then
        echo "  ERROR: El archivo es demasiado grande ($size bytes)"
        return 1
    else
        echo "  VALIDACIÓN EXITOSA: Tamaño correcto ($size bytes) `date`"
        return 0
    fi
}


echo "  Descargando $URL1..."
wget -q -O "$TEMP_FILE1" "$URL1"

# Validar descarga comprobando que el comando anterior no falla
if [ $? -ne 0 ]; then
    echo "  ERROR: Failed to download $URL1"
    rm -f "$TEMP_FILE1"
    exit 1 #abotar la ejecucion de este script
fi

echo "  Descargando $URL2..."
wget -q -O "$TEMP_FILE2" "$URL2"

# Validar descarga comprobando que el comando anterior no falla
if [ $? -ne 0 ]; then
    echo "  ERROR: Failed to download $URL2"
    rm -f "$TEMP_FILE2"
    exit 1 #abotar la ejecucion de este script
fi

echo "  Descargando $URL3..."
wget -q -O "$TEMP_FILE3" "$URL3"

# Validar descarga comprobando que el comando anterior no falla
if [ $? -ne 0 ]; then
    echo "  ERROR: Failed to download $URL3"
    rm -f "$TEMP_FILE3"
    exit 1 #abotar la ejecucion de este script
fi


# Validar tamano
if validate_size1 "$TEMP_FILE1"; then
    # Si pasa validación, renombrar archivo final
    mv "$TEMP_FILE1" "$FILE1"
    echo "  Descarga completada y validada: $FILE1"
else
    # Si falla, eliminar temporal
    rm -f "$TEMP_FILE1"
    exit 1
fi

# Validar tamano
if validate_size2 "$TEMP_FILE2"; then
    # Si pasa validación, renombrar archivo final
    mv "$TEMP_FILE2" "$FILE2"
    echo "  Descarga completada y validada: $FILE2"
else
    # Si falla, eliminar temporal
    rm -f "$TEMP_FILE2"
    exit 1
fi

# Validar tamano
if validate_size3 "$TEMP_FILE3"; then
    # Si pasa validación, renombrar archivo final
    mv "$TEMP_FILE3" "$FILE3"
    echo "  Descarga completada y validada: $FILE3"
else
    # Si falla, eliminar temporal
    rm -f "$TEMP_FILE3"
    exit 1
fi



echo "  Ejecutando: python3 process_send_report.py `date`"
python3 process_send_report.py >> $LOGFILE

TODAY=`date +%Y%m%d`
echo "  Finishing script on `date`" >> $LOGFILE
echo "     -------- ////// ------    " >> $LOGFILE

exit 0
