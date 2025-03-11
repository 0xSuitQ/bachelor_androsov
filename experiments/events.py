import tkinter as tk
from tkinter import ttk

def get_pos(event):
	print(f'x: {event.x} y: {event.y}')

window = tk.Tk()

text =tk.Text(window)
text.pack()

entry = ttk.Entry(window)
entry.pack()

button = ttk.Button(window, text='A Button')
button.pack()

# button.bind('<Command-KeyPress-a>', lambda event: print(event))
# window.bind('<KeyPress>', lambda event: print(event.char))
# window.bind('<Motion>', get_pos)

entry.bind('<FocusIn>', lambda event: print('Focused on Entry'))
entry.bind('<FocusOut>', lambda event: print('Unfocused from Entry'))

text.bind('<Shift-MouseWheel>', lambda event: print('MouseWheel'))

window.mainloop()