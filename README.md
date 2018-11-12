# iLightSln
A Python 3.6 client for iLightSln Zigbee gateways.
Provides blocking interface and non-blocking asyncio interface.

# Supported gateways
A compatible ILightSln gateway should shows a Wifi SSID during setup containing "iLightsln".
Many rebranded gateways are on the marked (e.g. from Renkforce and smart-mit-led).
A compatible gateway will likely tell you to install one of the following Android/iOS apps:
- iLightsln
- iSmartBulb
- iHookUp
- WiFi ER
- iWiFis
- Parify Smartlight 

# Usage: Blocking interface
```python
  from ilightsln import ilightsln
  lights = ilightsln.ILightSln(host='192.168.1.121')
  lights.add_lights_from_gateway()  # automatically receive lights
  lights.add_light('Kitchen Light', address=0xe24b)  # or add manually
  lights['Kitchen Light'].turn_on()  # access lights by name
  for light in lights.lights:  # or iterate
    light.turn_off()
  lights['Kitchen Light'].set_brightness(20)  # 1..100
  lights['Kitchen Light'].set_color_temp(20)  # 0..100  
```

# Usage: Non-blocking interface
```python
  from ilightsln import ilightsln
  loop = asyncio.get_event_loop()
  lights = ilightsln.ILightSln(host='192.168.1.121', loop=loop)
  asyncio.ensure_future(lights.async_add_lights_from_gateway())
  loop.run_forever() 
```
    
