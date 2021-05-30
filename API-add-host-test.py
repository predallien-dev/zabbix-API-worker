import os

# заготовка для скрипта для создания хостов заббикса используя имена файлов, расположенные в другом файле
# создает файлы из названий, прочитанных из другого файла, в данном случае "hosts.txt)

host_list = []
with open("hosts.txt") as file_in:  # добавляем в лист отдельным элементом каждую строку
    for line in file_in:
        line = line.rstrip('\n')
        host_list.append(line)
        print(host_list)

# получаем путь директории со скриптом, там создатутся файлы
path = os.path.join(os.path.dirname(os.path.abspath(__file__)))
print(path)

# итерируемя по листу и создаем файлы с названеием как у элементов листа
for i in range((len(host_list))):
    filename = host_list[i]
    with open (filename, 'w+'):
        pass