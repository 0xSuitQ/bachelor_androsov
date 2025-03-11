import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('600x400')

menu = tk.Menu(window)

file_menu = tk.Menu(menu, tearoff=False) # Not to create separate window
file_menu.add_command(label='New', command=lambda: print('New file'))
file_menu.add_command(label='Open', command=lambda: print('Open file'))
file_menu.add_separator()
file_menu.add_command(label='Delete', command=lambda: print('Delete file'))
menu.add_cascade(label='File', menu=file_menu)

help_menu = tk.Menu(menu, tearoff=False)
help_menu.add_command(label='Help entry', command=lambda: print(help_check_val.get()))
help_check_val = tk.StringVar()
help_menu.add_checkbutton(label='Check', onvalue='on', offvalue='off', variable=help_check_val)
menu.add_cascade(label='Help', menu=help_menu)

config_menu = tk.Menu(menu, tearoff=False)
menu.add_cascade(label='Configuration', menu=config_menu)

config_sub_menu = tk.Menu(config_menu, tearoff=False)
config_sub_menu.add_command(label='Entry 1', command=lambda: print('Entry 1'))
config_sub_menu.add_command(label='Entry 2', command=lambda: print('Entry 2'))
config_menu.add_cascade(label='Submenu', menu=config_sub_menu)
 
window.configure(menu=menu)


menu_button = ttk.Menubutton(window, text='Menu Button')
menu_button.pack()

button_sub_menu = tk.Menu(menu_button, tearoff=False)
button_sub_menu.add_command(label='Entry 1', command=lambda: print('Test 1'))
button_sub_menu.add_checkbutton(label='Check 1')
menu_button.configure(menu=button_sub_menu)

window.mainloop()