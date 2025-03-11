import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('600x400')

# Top frame
top_frame = ttk.Frame(window)
label1 = tk.Label(top_frame, text='First Label', background='red')
label2 = tk.Label(top_frame, text='Label 2', background='blue')

# Middle widget
label3 = tk.Label(window, text='Another label', background='green')

# Bottom frame
bottom_frame = ttk.Frame(window)
label4 = tk.Label(bottom_frame, text='Last of the labels', background='orange')
button = ttk.Button(bottom_frame, text='A Button')
button2 = ttk.Button(bottom_frame, text='Another Button')

# Top layout
label1.pack(side='left', fill='both', expand=True)
label2.pack(side='left', fill='both', expand=True)
top_frame.pack(fill='both', expand=True)

# Middle layout
label3.pack(fill='both', expand=True)

# Bottom layout
button.pack(side='left', expand=True, fill='both')
label4.pack(side='left', expand=True, fill='both')
button2.pack(side='left', expand=True, fill='both')
bottom_frame.pack(expand=True, fill='both', padx=20, pady=20)

window.mainloop()