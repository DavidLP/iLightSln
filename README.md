# iLightSln
Python client for iLightSln Zigbee gateways

# Usage
```python
  from ilightsln.ilightsln import ILightSln
  lights = ILightSln(host='192.168.1.121')
  lights.add_lights_from_gateway()  # automatically receive lights
  lights.add_light('Kitchen Light', address=0xe24b)  # or add manually
  lights['Kitchen Light'].turn_on()  # access lights by name
  for light in lights.lights:  # or iterate
    light.turn_off()
  lights['Kitchen Light'].set_brightness(20)  # 1..100
  lights['Kitchen Light'].set_color_temp(20)  # 0..100  
```
