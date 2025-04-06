import dearpygui.dearpygui as pygui
import psutil
import struct
import pymem

process = None
scan_matches = {}

def read_bytes(address, num_of_bytes):
  try:
    memory = process.read_bytes(address, num_of_bytes)
    return memory
  except ValueError:
    return None
  
def get_value_type(sender, data):
  if data == 'byte':
    pygui.set_value(sender, 1)
  elif data == '2 bytes':
    pygui.set_value(sender, 2)
  elif data == '4 bytes':
    pygui.set_value(sender, 4)
  elif data == '8 bytes': 
    pygui.set_value(sender, 8)

def scan():
  pass

def scan_for_bigger():
  pass

def scan_for_smaller():
  pass

def reset_scan_data():
  for item in scan_matches.items():
    print(item)

def scan_for_exact():
  if process is None:
    return None
  
  value_type = pygui.get_value('value_type')
  scan_value = pygui.get_value('scan_value') 
  if value_type == 'float':
    value_bytes = struct.pack('<f', float(scan_value))
  if value_type == 'string':
    value_bytes = scan_value.encode('utf-8')
  else:
    value_bytes = int(scan_value).to_bytes(int(value_type), 'little', signed=True)
  
  modules = list(process.list_modules())
  for module in modules:
    base_addr = module.lpBaseOfDll
    module_size = module.SizeOfImage
    
    module_memory = read_bytes(base_addr, module_size)
    
    if module_memory is not None:
      chunk_size = len(value_bytes)
      for addr in range(0, len(module_memory) - chunk_size + 1):
        bytes = module_memory[addr:addr+chunk_size]
        if bytes == value_bytes:
          found_addr = base_addr + addr
          
          global scan_matches 
          if len(scan_matches) > 0:
            new_matches = {}
            for _, match in scan_matches.items():
              if match['found_address'] is found_addr:
                new_matches[str(len(new_matches))] = {
                'module': module.name,
                'base_address': hex(base_addr),
                'offset': hex(addr),
                'found_address': hex(found_addr),
                'value': scan_value,
                'type': value_type
                }    
            scan_matches = new_matches
          else:
            scan_matches[str(len(scan_matches))] = {
              'module': module.name,
              'base_address': hex(base_addr),
              'offset': hex(addr),
              'found_address': hex(found_addr),
              'value': scan_value,
              'type': value_type
            }
    
def set_process(sender, data):
  global process
  process = pymem.Pymem(data)

def refresh_processes():
  new_processes = []
  for p in psutil.process_iter():
    new_processes.append(p.name())
  
  pygui.configure_item('process_list', items=new_processes)

def create_gui():
  pygui.create_context()
  
  pygui.create_viewport(title='PwnEngine', width=800, height=600, max_width=800, min_width=800, min_height=600, max_height=600)
  pygui.setup_dearpygui()
  
  with pygui.window(label='PwnEngine', no_title_bar=True, no_move=True, no_resize=True, no_scrollbar=True, width=800, height=600):
    def update_scan_table():
      if not pygui.does_item_exist('scan_data_table'):
        with pygui.table(tag='scan_data_table', header_row=True):
          pygui.add_table_column(label='Module')
          pygui.add_table_column(label='Base address')
          pygui.add_table_column(label='Offset')
          pygui.add_table_column(label='Address')
          pygui.add_table_column(label='Value')
          pygui.add_table_column(label='Type')
          
      pygui.delete_item('scan_data_table', children_only=True)
      with pygui.table(tag='scan_data_table'):
        for _, match in scan_matches.items():
          with pygui.table_row():
            pygui.add_text(label=f'{match['module']}')
            pygui.add_text(label=f'{match['base_address']}')
            pygui.add_text(label=f'{match['offset']}')
            pygui.add_text(label=f'{match['found_address']}')
            pygui.add_text(label=f'{match['value']}')
            pygui.add_text(label=f'{match['type']}')
  
            
    with pygui.table(tag='scan_data_table', header_row=True):
      pygui.add_table_column(label='Module')
      pygui.add_table_column(label='Base address')
      pygui.add_table_column(label='Offset')
      pygui.add_table_column(label='Address')
      pygui.add_table_column(label='Value')
      pygui.add_table_column(label='Type')
    
    pygui.add_button(label='Update scan table', callback=update_scan_table)
    
    pygui.add_combo([], tag='process_list', label='Process List', default_value='Select a process', width=200, callback=set_process)
    pygui.add_button(label='Refresh', callback=refresh_processes)
    
    pygui.add_input_text(label='Value:', tag='scan_value')
    pygui.add_combo(['byte', '2 bytes', '4 bytes', '8 bytes', 'float', 'string'], tag='value_type', label='Value type:', default_value='byte', width=200, callback=get_value_type)
    pygui.add_button(label='Scan for exact value', callback=scan_for_exact)
    pygui.add_button(label='Scan for bigger', callback=scan_for_bigger)
    pygui.add_button(label='Scan for smaller', callback=scan_for_smaller)
    pygui.add_button(label='Reset scan data', callback=reset_scan_data)
  
  pygui.show_viewport()
  pygui.start_dearpygui()
  pygui.destroy_context()
  
  
if __name__ == '__main__':
  create_gui()