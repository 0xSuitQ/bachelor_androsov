import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.title('Combobox and spinbox')
window.geometry('600x400')

# Combobox
items = ('Pizza', 'Broccoli', 'Ice Cream')
food_string = tk.StringVar(value = items[0])
combo = ttk.Combobox(window, textvariable=food_string)
combo['values'] = items
combo.pack()

combo.bind('<<ComboboxSelected>>', lambda event: combo_label.configure(text = f'Selected value is {food_string.get()}'))

combo_label = ttk.Label(window, text='Nothing is selected')
combo_label.pack()


# Spinbox

spin_int = tk.IntVar(value=10)
spin = ttk.Spinbox(window, from_=5, to=20, increment=5, command=lambda: print(spin_int.get()), textvariable=spin_int)
spin.pack()

spin.bind('<<Increment>>', lambda event: print('Up'))
spin.bind('<<Decrement>>', lambda event: print('Down'))

spin_letters = ('A', 'B', 'C', 'D', 'E')
spin_val = tk.StringVar(value=spin_letters[0])
spinbox = ttk.Spinbox(window, textvariable=spin_val, values=spin_letters)
spinbox.pack()

spinbox.bind('<<Decrement>>', lambda event: print(f'The value is {spin_val.get()}'))

window.mainloop()
