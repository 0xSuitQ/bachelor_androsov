import tkinter as tk
from tkinter import ttk

def button_func():
	string_var.set('Button is pressed')

window = tk.Tk()
window.title('TKinter Variables')

string_var = tk.StringVar()

label = ttk.Label(window, text='label', textvariable=string_var)
label.pack()

entry = ttk.Entry(window, textvariable=string_var)
entry.pack()

button = ttk.Button(window, text='button', command=button_func)
button.pack()

window.mainloop()