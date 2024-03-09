from socket import *
from ssl import *
import random
import threading
import argparse
import sys, os, time, re, datetime
import numpy as np

# Настройка порта
def setPort():
    # Используется для получения от пользователя порта
    # Проверяет соответствие диапазону портов и типу данных
    # В случае нажатия Ctrl+C - останавливает программу
    # При неправильных данных - рекурсивный вызов
    try:
        PORT = input()
        if PORT == "":
            PORT = 50000
            return PORT
        else:
            if ((int(PORT) < 65535) & (int(PORT) > 0)):
                return int(PORT)
            else: 
                print("Порт некорректный! Попробуйте еще раз:")
                return setPort()
    except KeyboardInterrupt:
        sys.exit(0)
    except:
        return setPort()

# Проверка IP
def isValidIP(ip):
    # Проверка IP по регулярному выражению
    # RE: 1-3 цифры 4 раза с разделителем - точка
    # Затем проверка каждых групп цифр на корректность
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

# Меню
def createMenu(role=None, seed=None, seed_position=None, DEBUG_MODE=False,IP=None, Port=None, clientADDR=None):
    # Очищает экран
    # Печатает логотип и переданные параметры в консоль
    # Работает при передаче какого-либо параметра и в совокупности
    os.system('cls' if os.name == 'nt' else 'clear')
    startMenu()
    if role is not None:
        if role ==1:
            print("РОЛЬ:   {client_}".format(client_="КЛИЕНТ"))
        elif role==0:
            print("РОЛЬ:   {server_}".format(server_="СЕРВЕР"))
    if seed is not None:
        print("SEED:\t{seed_}".format(seed_=seed))
    if ((seed is not None) & (DEBUG_MODE == True)):
        print("SEED:\t{seed_position_}".format(seed_position_=seed_position))
    if IP is not None:
        print("HOST:\t{IP_}".format(IP_=IP))
    if Port is not None:
         print("PORT:\t{Port_}".format(Port_=Port))
    if clientADDR is not None:
        print("ADDR:\t{clientADDR_}".format(clientADDR_=clientADDR))

# Логотип
def startMenu():
    print("--------------------------------------------------------------")
    print("-- Steganography layer before TLS for compromised networks! --")
    print("--------------------------------------------------------------")

# Целевой IP
def aimIP():
    print("Вы ожидаете подключения с определенного IP? 0 - нет, 1- да")
    try:
        role = int(input())
        if ((int(role)>1) | (int(role)<0)):
            print("Допустимые значения: 1 и 0")
            time.sleep(1)
            return aimIP()
        else:
            if role == 0:
                return None
            if role == 1:
                print("Введите целевой IP:")
                aimADDR = input()
                while isValidIP(aimADDR) == False:
                    print("Введите корректный IP!")
                    aimADDR = input()
                return aimADDR
    except KeyboardInterrupt:
        sys.exit(0)
    except:
        return aimIP()

# Роль
def setRole():
    # Очищает экран, добавляет стартовое меню
    # Поулчает тип int 0-сервер, 1-клиент
    # При ошибке - рекурсивный вызов
    os.system('cls' if os.name == 'nt' else 'clear')
    startMenu()
    print("Ваша роль:\t0 - сервер \n\t\t1 - клиент")
    try:
        role = int(input())
        if ((int(role)>1) | (int(role)<0)):
            print("Допустимые значения: 1 и 0")
            time.sleep(1)
            return setRole()
        else:
            return role
    except KeyboardInterrupt:
        sys.exit(0)
    except:
        return setRole()

# Печать в консоль по 21 байту
def printHEX(message):
    try:
        s = ' '.join(bytes(message).hex()[i:i+2] for i in range(0, len(bytes(message).hex()), 2))
    except:
        s = ' '.join(bytes(message, encoding='utf-8').hex()[i:i+2] for i in range(0, len(bytes(message,encoding='utf-8').hex()), 2))
    for i in range(0,len(s)):
        if ((i%63 != 0) | (i==0)):
            print(s[i], end='')
        elif ((i%63==0) & (i!=0)):
            print("\n{s}".format(s=s[i]), end='')
    print()

# Определение разрядов числа
def countCapacity(number):
    number = abs(number)
    capacity = 1
    number //= 10
    while number > 0:
        number //= 10
        capacity += 1
    return capacity

# Генерация рандомных байтов
def randomByte(pckt_len):
    random_bytes = random.randbytes(pckt_len)
    return random_bytes

# XOR байтов
def bxor(bytes_1st, bytes_2nd):
    result = bytearray(bytes_1st)
    for i, b in enumerate(bytes_2nd):
        result[i] ^= b
    return bytes(result)

# Обработка полученных сообщений
def onRecieved(client, MAX_BUFFER_SIZE, DEBUG_MODE, WRITE_MODE, file, server=None):

    # Флаг для обмена информацией о закрытии подключения
    # Используется в onRecieved и onSend
    global Flag

    # Основной цикл
    while Flag:
        # Поле для секретного сообщения
        message = b''
        # Получение пакета с сокета
        recv_packet = client.recv(MAX_BUFFER_SIZE)
        # Проверка на изменение состояния флага
        if Flag == False:
            client.close()
            if WRITE_MODE==True:
                file.close()
            if server is not None:
                server.close()
            break

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПолученный пакет: ")
            printHEX(recv_packet)
        if WRITE_MODE==True:
            file.write("\n{date_}\nПолученный пакет: {recv_packet_}".format(date_ = str(datetime.datetime.now()),recv_packet_=bytes(recv_packet).hex())) 
        #--------------------------------------------------

        # Длина полученного пакета
        length_recv_packet = len(recv_packet)

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE ==True:
            print("\nДлина полученного пакета: ", length_recv_packet)
        if WRITE_MODE==True:
            file.write("\nДлина полученного пакета: {length_}".format(length_=length_recv_packet)) 
        #--------------------------------------------------

        # Случайные байты с длиной полученного пакета
        rand_bytes = randomByte(length_recv_packet)
        # Поле для 3-х байт длины сообщения
        message_length = b''

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nСлучайный пакет: ")
            printHEX(rand_bytes)
        if WRITE_MODE==True:
            file.write("\nСгенерированный случайный пакет: {rand_bytes_}".format(rand_bytes_=bytes(rand_bytes).hex()))
        #--------------------------------------------------

        # Извлечение байт сообщения из контейнера
        message_deXOR = bxor(rand_bytes, recv_packet)

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nИзвлеченные случайные байты из пакета:")
            printHEX(message_deXOR)
        if WRITE_MODE==True:
            file.write("\nИзвлеченные случайные байты из пакета: {message_deXOR_}".format(message_deXOR_=bytes(message_deXOR).hex()))
        #--------------------------------------------------

        # Генерация позиций для определения позиций длины сообщения
        length_positions = np.random.permutation(length_recv_packet)[:3].tolist()

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПозиции байтов для хранения длины сообщения:\n", length_positions)
        if WRITE_MODE==True:
            file.write("\nПозиции байтов для хранения длины сообщения: {length_positions_}".format(length_positions_=length_positions))
        #--------------------------------------------------

        # Получение байтов, отвечающих за длину сообщения
        try:
            for i in range(0,3):
                    message_length += bytes(message_deXOR[length_positions[i]:length_positions[i]+1])
        except:
            if WRITE_MODE==True:
                file.write("\nНе удалось получить длину сообщения, несовпадение параметров!\n(возможно сервер отклонил запрос на подключение)")
                file.close()
            print("\nНе удалось получить длину сообщения, несовпадение параметров!\n(возможно сервер отклонил запрос на подключение)\nНажмите enter для завершения...")
            Flag = False
            client.close()
            if server is not None:
                    server.close()
            break

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            s = ' '.join(message_length.hex()[i:i+2] for i in range(0, len(message_length.hex()), 2))
            print("\nБайты длины сообщения:\n", s)
        if WRITE_MODE==True:
            file.write("\nБайты длины сообщения: {message_length_}".format(message_length_=message_length.hex()))     
        #--------------------------------------------------   

        # Конвертация байтов длины сообщения в число
        try:
            message_length = int(message_length)
        except:
            if WRITE_MODE==True:
                file.write("\nНе удалось получить длину сообщения, нет синхронизации!")
                file.close()
            print("\nНе удалось получить длину сообщения, нет синхронизации! Нажмите enter для завершения...")
            Flag = False
            client.close()
            if server is not None:
                    server.close()
            break

        # Определение порядка байтов сообщения и их позиций
        # Запас на 3 позиции необходим при совпадении их с позициями байтов длины сообщения
        message_bytes_positions = np.random.permutation(length_recv_packet)[:message_length+3].tolist()

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПозиции байтов внедренного сообщения:\n" , message_bytes_positions)
        if WRITE_MODE==True:
            file.write("\nПозиции байтов внедренного сообщения: {message_bytes_positions_}".format(message_bytes_positions_=message_bytes_positions))
        #--------------------------------------------------           

        # Удаление возможных повторяющихся позиций 
        for i in range(0,len(length_positions)):
            try:
                message_bytes_positions.remove(length_positions[i])
            except:
                pass

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПозиции байтов внедренного сообщения без позиций байтов длины:\n", message_bytes_positions)
        if WRITE_MODE == True:
            file.write("\nПозиции байтов внедренного сообщения без позиций байтов длины: {message_bytes_positions_}".format(message_bytes_positions_=message_bytes_positions))
        #--------------------------------------------------      

        # Собираем байты по порядку в соответствии с позициями
        for i in range(0,message_length):
            message += message_deXOR[message_bytes_positions[i]:message_bytes_positions[i]+1]

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nБайты полученного сообщения:")
            printHEX(message)
        if WRITE_MODE==True:
            file.write("\nБайты полученного сообщения: {message_}".format(message_=message.hex()))
        #--------------------------------------------------   

        # Конвертация байтовой строки в строку Unicode
        message = str(message, encoding='utf-8')

        #--------------- Выдача результатов ---------------
        if WRITE_MODE==True:
            file.write("\nПолученное сообщение: {message_}".format(message_=message))
            file.write("\n")
        #--------------------------------------------------   

        # Если получено сообщение о конце диалога обеспечить завершение работы
        # Иначе вывести полученное сообщение
        if ((message =="!EoD!")&(Flag==True)):
            print("\nСобеседник завершил диалог! Нажмите enter для завершения...")
            if WRITE_MODE==True:
                file.write("\nДиалог был завершен!\n\n")
                file.close()
            client.close()
            if server is not None:
                    server.close()
            Flag = False
        else:
            print("Получено сообщение: ", message)


# Отправка сообщений
def onSend(client, MAX_BUFFER_SIZE, DEBUG_MODE, WRITE_MODE, file, server=None):

    # Флаг для обмена информацией о закрытии подключения
    # Используется в onRecieved и onSend
    global Flag

    # Генератор для длины пакета
    pckt_length = random.Random()
    
    # Основной цикл
    while Flag:

        # Пользовательский ввод (Ctrl+C - завершение диалога)
        try:
            message_to_send = input()
            if Flag == True:
                while ((message_to_send.isspace())|(message_to_send=='')|(len(bytes(message_to_send,encoding='utf-8'))>600)):
                    if Flag == True:
                        print("Ошибка: сообщение больше 600 байт и/или состоит из пробелов")
                        message_to_send = input()
            else: 
                if WRITE_MODE==True:
                    file.close()
                break
        except KeyboardInterrupt:
            print("Завершаем диалог штатно...")
            message_to_send = "!EoD!"

        # Если флаг был изменен - выйти из цикла
        if Flag == False:
            break

        # Сохраняем первоначальное сообщение, печатаем длину стегосообщения
        message = message_to_send

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nДлина сообщения: ", len(bytes(message,encoding='utf-8')))
        if WRITE_MODE==True:
            file.write("\n{date_}\nОтправленное сообщение: {message_} \nДлина отправленного сообщения:{length_}".format(date_ = str(datetime.datetime.now()),message_=message, length_=len(bytes(message,encoding='utf-8'))))
        #-------------------------------------------------- 

        # Заполняем 3 байта длины сообщения (необходимо обеспечить 3 разряда в числе)
        length = countCapacity(len(bytes(message_to_send,encoding='utf-8')))

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nРазрядность длины:",length)
        if WRITE_MODE==True:
            file.write("\nРазрядность длины: {length_}".format(length_=length))
        #-------------------------------------------------- 

        # Дополнение длины до 3-х разрядов в типе string
        if length == 3:
            length = str(len(bytes(message_to_send,encoding='utf-8')))
        if length == 2:
            length = str(0) + str(len(bytes(message_to_send,encoding='utf-8')))
        if length == 1:
            length = str(0) + str(0) + str(len(bytes(message_to_send,encoding='utf-8')))

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nЗначение длины в 3-х разрядной форме:", length)
        if WRITE_MODE==True:
            file.write("\nЗначение длины в 3-х разрядной форме: {length_}".format(length_=length))
        #--------------------------------------------------

        # Длина пакета определяется случайно в диапазоне (длина пакета, максимальный размер пакета)
        length_send_packet =  pckt_length.randint(len(bytes(message, encoding='utf-8'))+3,MAX_BUFFER_SIZE)

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nСлучайная длина пакета для внедрения сообщения: ", length_send_packet)
        if WRITE_MODE==True:
            file.write("\nСлучайная длина пакета для внедрения сообщения: {length_}".format(length_=length_send_packet))
        #--------------------------------------------------

        # Позиции для байтов, отвечающих за длину стегосообщения
        length_positions = np.random.permutation(length_send_packet)[:3].tolist()

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПозиции байтов для внедрения байтов длины сообщения:\n", length_positions)
        if WRITE_MODE==True:
            file.write("\nПозиции байтов для внедрения байтов длины сообщения: {length_}".format(length_=length_positions))
        #--------------------------------------------------

        # Позиции для байтов стегосообщения 
        # Запас на 3 позиции необходим при совпадении их с позициями байтов длины сообщения
        message_bytes_positions = np.random.permutation(length_send_packet)[:(len(bytes(message, encoding='utf-8'))+3)].tolist()

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПозиции байтов для внедрения байтов сообщения:\n" , message_bytes_positions)
        if WRITE_MODE==True:
            file.write("\nПозиции байтов для внедрения байтов сообщения: {positions_}".format(positions_=message_bytes_positions))
        #--------------------------------------------------

        # Удаление позиций для байтов сообщения занятых байтами длины
        for i in range(0,len(length_positions)):
            try:
                message_bytes_positions.remove(length_positions[i])
            except:
                pass
        
        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nПозиции байтов для внедрения сообщения исключая позиции байтов длины:\n", message_bytes_positions)
        if WRITE_MODE==True:
            file.write("\nПозиции байтов для внедрения сообщения исключая позиции байтов длины: {positions_}".format(positions_=message_bytes_positions))
        #--------------------------------------------------

        # Генерация случайных байт для контейнера
        rand_bytes_send = randomByte(length_send_packet)

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nСлучайный пакет:")
            printHEX(rand_bytes_send)
        if WRITE_MODE==True:
            file.write("\nСлучайный пакет: {rand_bytes_send_}".format(rand_bytes_send_=bytes(rand_bytes_send).hex()))
        #--------------------------------------------------

        # Преобразование в bytearray
        rand_bytes_send = bytearray(rand_bytes_send)

        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nБайты сообщения:")
            printHEX(message_to_send)
        if WRITE_MODE==True:
            file.write("\nБайты сообщения: {message_to_send_}".format(message_to_send_=bytes(message_to_send,encoding='utf-8').hex()))
        #--------------------------------------------------
            
        # Преобразование в bytearray
        message_to_send = bytearray(message_to_send, encoding='utf-8')
        
        # Преобразование в bytearray
        length = bytearray(length, encoding='utf-8')

        # XOR байтов контейнера с байтами длины сообщения
        for i in range(0,3):
            rand_bytes_send[length_positions[i]] = rand_bytes_send[length_positions[i]] ^ length[i]

        # XOR байтов контейнера с байтами сообщения
        for i in range(0,len(message_to_send)):
            rand_bytes_send[message_bytes_positions[i]] = rand_bytes_send[message_bytes_positions[i]] ^ message_to_send[i]
        
        #--------------- Выдача результатов ---------------
        if DEBUG_MODE == True:
            print("\nСлучайные байты с встроенным сообщением:")
            printHEX(rand_bytes_send)
        if WRITE_MODE==True:
            file.write("\nОтправленные байты со стегосообщением: {message_}".format(message_=bytes(rand_bytes_send).hex()))
            file.write("\n")
        #--------------------------------------------------

        # Если введено сообщение-триггер на завершение диалога, 
        # устанавливаем флаг, отправляем сообщение, завершаем подключение
        # Иначе отправляем сообщение
        if ((message=="!EoD!")&(Flag==True)):
            print("Завершаем диалог...")
            if WRITE_MODE==True:
                file.write("\nДиалог был завершен!")
                file.write("\n\n")
                file.close()
            Flag = False
            client.send(bytes(rand_bytes_send))
            client.close()
            if server is not None:
                    server.close()
            break
        else:
            try:
                client.send(bytes(rand_bytes_send))
            except:
                if WRITE_MODE==True:
                    file.write("Подключение прервано")
                    file.write("\n\n")
                    file.close()
                print("Подключение прервано")

# Точка входа в приложение
def main(seed,seed_position,role,MAX_BUFFER_SIZE, DEBUG_MODE, WRITE_MODE):

    # Роль - сервер
    if (role==0):

        # Информация об IP/hostname сервера
        print("Введите IP адрес:")
        try: 
            HOST = input()
            if HOST == "":
                #По умолчанию
                HOST='localhost' 
            else:
                while (isValidIP(HOST)==False):
                    print("IP адрес некорректный! Попробуйте еще раз:")
                    HOST = input()
        except KeyboardInterrupt:
            sys.exit(0)
        
        # Печатаем результаты ввода
        createMenu(role,seed, seed_position, DEBUG_MODE,HOST)
  
        # Информация о порте сервера
        print("Введите порт (от 0 до 65535), по умолчанию: 50000")
        PORT = setPort()

        # Печатаем результаты ввода
        createMenu(role, seed, seed_position, DEBUG_MODE, HOST, PORT)

        # создаем кортеж с данными о сервере
        SERVER = (HOST, PORT)
        
        # Установка серверного поведения в протоколе
        sslctx = SSLContext(PROTOCOL_TLS_SERVER)
        
        # Логгирование сессионных ключей
        if ((DEBUG_MODE==True) | (WRITE_MODE==True)):
            sslctx.keylog_filename = "secrets.log"
        
        # Подключение сертификата и приватного ключа
        try:
            sslctx.load_cert_chain('certificate.pem', 'private.key')
        except:
            if WRITE_MODE==True:
                file.write("\nСертикат или ключ не найден!")
                file.close()
            print("Сертификат или ключ не найден")

        # Враппинг сокета, биндинг и прослушивание
        try:
            server = sslctx.wrap_socket(socket(AF_INET , SOCK_STREAM), server_side=True)
            server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server.bind(SERVER) 
        except KeyboardInterrupt:
            print("Выход из программы!")
            if WRITE_MODE==True:
                file.write("\nКоманда на выход из программы")
                file.close()
            sys.exit(0)
        except:
            print("Введены некорректные данные (IP и/или занят PORT)")
            if WRITE_MODE==True:
                file.write("\nОшибка в IP, PORT (занят порт?)")
                file.close()
            sys.exit(0)

        # Запрос целевого IP, если имеется
        clientADDR = aimIP()
        createMenu(role, seed, seed_position, DEBUG_MODE, HOST, PORT, clientADDR)

        # Запись данных в файл
        if WRITE_MODE==True:
            file = open("SERVER.txt", "a")
            file.write("{date_}".format(date_ = str(datetime.datetime.now())))
            file.write("\nРоль: СЕРВЕР \nSEED1: {seed_} \nSEED2: {seed_position_} \nDEBUG: {DEBUG_MODE_} \nHOST: {HOST_} \nPORT: {PORT_}\nADDR: {clientADDR_}\n\n".format(seed_=seed, seed_position_=seed_position,DEBUG_MODE_=DEBUG_MODE,HOST_=HOST,PORT_=PORT,clientADDR_=clientADDR))

        print('\nНапоминание:\n1. Максимальная длина сообщения 600 байт \n(300 букв на русском, 600 букв на английском)')
        print('2. Цифры и стандартные специальные символы занимают 1 байт')
        print('3. Для выхода из диалога нажмите Ctrl+C или введите !EoD!\n')
        print('-------------- Сервер запущен, ждем подключения --------------')
    
        # Подключение клиента и обработка события подключения
        try: 
            server.listen(1)
            client, address = server.accept()
            if clientADDR is not None:
                while address[0] != clientADDR:
                    client.close()
                    server.listen(1)
                    client, address = server.accept()
            print("---------------- Подключился: {address_ip}:{address_port} ----------------".format(address_ip=address[0],address_port=address[1]))
        except KeyboardInterrupt:
            print("Выход из программы!")
            if WRITE_MODE==True:
                file.write("\nКоманда на выход из программы")
                file.close()
            server.close()
            sys.exit(0)
        except:
            print("Недучаная попытка подключения...\nНедействительный пользовательский сертификат!") 
            if WRITE_MODE==True:
                file.write("\nНедействительный пользовательский сертификат")
                file.close()
            try:
                server.close()
                sys.exit(0)
            finally:
                sys.exit(0)

        # Если WRITE_MODE = False определяем файл типом None
        if WRITE_MODE == False:
            file = None

        # Запуск отдельного потока на получение сообщений
        # Основной поток используется для отправки сообщений
        try:
            recieve_thread = threading.Thread(target=onRecieved, args=[client, MAX_BUFFER_SIZE,DEBUG_MODE, WRITE_MODE, file, server])
            recieve_thread.start()
            onSend(client, MAX_BUFFER_SIZE, DEBUG_MODE, WRITE_MODE, file,server)
        except KeyboardInterrupt:
            pass

        # Завершение подключения
        client.close()
        server.close()

    elif (role==1): 
        
        # Информация об IP/hostname сервера
        print("Введите IP адрес сервера:")
        try: 
            HOST = input()
            if HOST == "":
                #По умолчанию
                HOST='localhost' 
            else:
                while (isValidIP(HOST)==False):
                    print("IP адрес сервера некорректный! Попробуйте еще раз:")
                    HOST = input()
        except KeyboardInterrupt:
            sys.exit(0)

        # Печать изменений конфигурации в консоль
        createMenu(role,seed, seed_position, DEBUG_MODE,HOST)

        # Получение порта
        print("Введите порт сервера (от 0 до 65535), по умолчанию: 50000")
        PORT = setPort()

        # Печать изменений конфигурации в консоль
        createMenu(role, seed, seed_position, DEBUG_MODE, HOST, PORT)

         # Генерируем файл для записи в него информации
        if WRITE_MODE==True:
            file = open("CLIENT.txt", "a")
            file.write("{date_}".format(date_ = str(datetime.datetime.now())))
            file.write("\nРоль: КЛИЕНТ \nSEED1: {seed_} \nSEED2: {seed_position_} \nDEBUG: {DEBUG_MODE_} \nHOST: {HOST_} \nPORT: {PORT_}\n\n".format(seed_=seed, seed_position_=seed_position,DEBUG_MODE_=DEBUG_MODE,HOST_=HOST,PORT_=PORT))

        # создаем кортеж с данными о сервере
        SERVER = (HOST, PORT)
        
        # Установка клиентского поведения в протоколе
        sslctx = SSLContext(PROTOCOL_TLS_CLIENT)

        # Логгирование сессионных ключей SSL
        if ((DEBUG_MODE==True)|(WRITE_MODE==True)):
            sslctx.keylog_filename = "secrets.log"

        # Подключение сертификата
        try: 
            sslctx.load_verify_locations('certificate.pem')
        except:
            if WRITE_MODE==True:
                file.write("\nСертикат или ключ не найден!")
                file.close()
            print("Сертификат не найден!")

        # Печать правил в консоль
        print('\nНапоминание:\n1. Максимальная длина сообщения 600 байт \n(300 букв на русском, 600 букв на английском)')
        print('2. Цифры и стандартные специальные символы занимают 1 байт')
        print('3. Для выхода из диалога нажмите Ctrl+C или введите !EoD!\n')

        # Подключение к серверу
        try: 
            client = sslctx.wrap_socket(socket(AF_INET , SOCK_STREAM), server_hostname=HOST)
            client.settimeout(10)
            client.connect(SERVER)
            client.settimeout(None)
            print("-------------------- Подключение успешно! --------------------")
        except timeout:
            if WRITE_MODE==True:
                file.write("\nНе удалось подключиться. Превышено время ожидания ответа от сервера.")
                file.close()
            print("-------------- Вышло время ожидания подключения --------------")
            try:
                client.close()
            except:
                pass
            sys.exit(0)
        except:
            if WRITE_MODE==True:
                file.write("\nНе удалось подключиться.")
                file.close()
            print("-------------- Подключение не удалось выполнить --------------")
            try:
                client.close()
            except:
                pass
            sys.exit(0)

        # Если WRITE_MODE = False определяем файл типом None
        if WRITE_MODE == False:
            file = None

        # Запуск отдельного потока на получение сообщений
        # Основной поток используется для отправки сообщений
        try:
            recieve_thread = threading.Thread(target=onRecieved, args=[client, MAX_BUFFER_SIZE, DEBUG_MODE, WRITE_MODE, file])
            recieve_thread.start()
            #Запускаем функцию отправки сообщений
            onSend(client, MAX_BUFFER_SIZE, DEBUG_MODE, WRITE_MODE, file)
        except KeyboardInterrupt:
            pass
        client.close()

# Инициализация при запуске
if __name__=="__main__":

    # Парсинг аргументов для определения режима работы
    parser = argparse.ArgumentParser(description='Стеганография с имитацией трафика.')
    parser.add_argument('-m','--mode', help='Если выбран режим "debug", то в консоль будет выводится дополнительная информация.', default="normal")
    parser.add_argument('-f','--file', help='Если выбран "true", то будет производится запись информации в файл (будет записана и дополнительная информация).', default="false")
    args = parser.parse_args()

    # Запуск режима работы с отладкой
    # Иначе запуск нормального режима работы
    if (str(args.mode).lower() == "debug"):
        DEBUG_MODE = True
    else:
        DEBUG_MODE = False

    # Запуск режима работы с печатью в файл
    # Иначе запуск нормального режима работы
    if (str(args.file).lower() == "true"):
        WRITE_MODE = True
    else:
        WRITE_MODE = False

    # Максимальный размер ввода (кириллица - 300 букв, латиница - 600 букв)
    MAX_BUFFER_SIZE = 603

    # Инициализация флага запуска потоков
    Flag = True

    # Установка роли
    role = setRole()

    # Вывод результатов
    os.system('cls' if os.name == 'nt' else 'clear')
    startMenu()
    createMenu(role)

    # Логгирование ключей
    os.environ["SSLKEYLOGFILE"] = "secrets.log"
    print("Введите ключевую фразу: (SEED, default='olegulanov')")

    # Получение сида
    try:
        seed = str(input())
        if seed=="":
            seed = "olegulanov"
    except KeyboardInterrupt:
        sys.exit(0)
    
    # Генерация второго сида
    seed_position = (int.from_bytes(bytes(seed, encoding='utf-8'), byteorder="big") % 4294967295) #2**32-1
    createMenu(role, seed, seed_position, DEBUG_MODE)

    # Инициализация генераторов сидами
    random.seed(seed,version=2)
    np.random.seed(seed_position)

    # Запуск основной программы
    main(seed,seed_position,role,MAX_BUFFER_SIZE, DEBUG_MODE,WRITE_MODE)