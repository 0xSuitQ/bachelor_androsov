import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('600x400')

# Widgets
label1 = tk.Label(window, text='Label1', background='red')
label2 = tk.Label(window, text='Label2', background='blue')
label3 = tk.Label(window, text='Label3', background='green')
label4 = tk.Label(window, text='Label4', background='yellow')
button1 = tk.Button(window, text='Button1')
button2 = tk.Button(window, text='Button2')

# Define a grid
window.columnconfigure((0, 1, 2), weight=1, uniform='a') # uniform = 'a' to make empty space equal size
window.columnconfigure(3, weight=5, uniform='a')
window.rowconfigure((0, 1, 2), weight=1, uniform='a')
window.rowconfigure(3, weight=4, uniform='a')

# Layout
label1.grid(row=0, column=0, sticky='nsew')
label2.grid(row=1, column=1, columnspan=2, sticky='nsew', padx=20, pady=10)
label3.grid(row=2, column=1, sticky='nsew')
label4.grid(row=3, column=3, sticky='nsew')
button1.grid(row=2, column=2, pady=10, sticky='nsew')

window.mainloop()