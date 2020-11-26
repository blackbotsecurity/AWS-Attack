import os

current_directory = os.getcwd()
'''
for root, directories, files in os.walk('{}/ttp'.format(current_directory)):
    ttp_directory_path = os.path.realpath('{}/ttp'.format(current_directory))
    specific_technique_directory = os.path.realpath(root)

    print(ttp_directory_path)
    print(specific_technique_directory)
    print(os.path.basename(root))

    #if os.path.basename(root) == 'ttp':
    for file in files:
        if file[:-3] == '.py':

            print(file)
'''


current_directory = os.getcwd()
(_, _, filenames) = next(os.walk(f'{current_directory}/ttp'))
print(filenames)
for c in filenames:
    print(c[:-3])
    if c[:-3] == '.py':
        print(c)
