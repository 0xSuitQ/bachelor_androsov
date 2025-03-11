import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.title('Buttons')
window.geometry('600x400')

button_string = tk.StringVar(value='A button with string var')
button = ttk.Button(window, text='A button', textvariable=button_string, command=lambda: print(radio_var.get()))
button.pack()

check_var = tk.IntVar(value=10)
check1 = ttk.Checkbutton(window, 
						text='checkbox 1', 
						variable=check_var, 
						command=lambda: print(check_var.get()),
						onvalue=10,
						offvalue=5)
check1.pack()

check2 = ttk.Checkbutton(window, text='checkbox 2', command=lambda: check_var.set(5))
check2.pack()

radio_var = tk.StringVar()
radio1 = ttk.Radiobutton(window, text='Radiobutton 1', value='option 1', variable=radio_var)
radio2 = ttk.Radiobutton(window, text='Radiobutton 2', value=2, variable=radio_var)
radio1.pack()
radio2.pack()

window.mainloop()