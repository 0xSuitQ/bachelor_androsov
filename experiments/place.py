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
button2 = ttk.Button(window, text='Button2')

# Frame
frame = ttk.Frame(window)
frame_label = tk.Label(frame, text='Form Label', background='red')
frame_button = tk.Button(frame, text='Frame Button')

# Layout
label1.place(x=100, y=350, width=300, height=50)
label2.place(relx=0.5, rely=0.2, relwidth=0.4, relheight=0.5)
button2.place(relx=1, rely=1, anchor='se')

# Frame layout
frame.place(relx=0, rely=0, relwidth=0.3, relheight=1)
frame_label.place(relx=0, rely=0, relwidth=1, relheight=0.5) # place() is relative to the container
frame_button.place(relx=0, rely=0.5, relwidth=1, relheight=0.5)

window.mainloop()